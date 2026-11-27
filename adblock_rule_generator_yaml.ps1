# 【项目标题】AdBlock_Rule_For_Clash
# 【核心功能】从多个上游广告过滤源抓取规则，经精确解析后转换为Clash兼容的 DOMAIN-SUFFIX 与 DOMAIN 格式，最终生成clash规则集文件
# 【项目主页】https://github.com/REIJI007/AdBlock_Rule_For_Clash
# 【开源协议1】GPL-3.0 
# 【开源协议2】CC-BY-NC-SA 4.0

# ── 上游规则源列表 ────────────────────────────────────────────────────────────
$urlList = @(
		"https://adaway.org/hosts.txt",
		"https://filters.adavoid.org/ultimate-ad-filter.txt",
		"https://filters.adavoid.org/ultimate-privacy-filter.txt",
		"https://filters.adavoid.org/ultimate-security-filter.txt",
		"https://secure.fanboy.co.nz/fanboy-annoyance.txt",
		"https://secure.fanboy.co.nz/fanboy-annoyance_ubo.txt",
		"https://secure.fanboy.co.nz/fanboy-cookiemonster.txt",
		"https://secure.fanboy.co.nz/fanboy-problematic-sites.txt",
		"https://easylist.to/easylist/easylist.txt",
		"https://easylist.to/easylist/easyprivacy.txt",
		"https://easylist.to/easylist/fanboy-social.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers_popup.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist_dimensions.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist_general_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist_popup.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_block.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_block_dimensions.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_block_popup.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_specific_block.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_specific_block_popup.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_specific_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_specific_hide_abp.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty_popup.txt",
		"https://raw.githubusercontent.com/easylist/easylistchina/master/easylistchina.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_allowlist.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_allowlist_international.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_general.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_general_emailtrackers.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_abp.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_a8net.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_acton.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_ad-ebis.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_adobe.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_at-internet.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_branch.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_commanders-act.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_criteo.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_dataunlocker.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_eulerian.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_ingenious-technologies.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_keyade.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_lead-forensics.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_np6.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_oracle.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_otto.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_plausible.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_tracedock.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_webtrekk.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_wizaly.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_international.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_perimeterx.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_uBO.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty_international.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_admiral.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_general.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_international.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_mining.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_notifications.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_thirdparty.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_allowlist.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_allowlist_general_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_general_block.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_general_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_international_specific_block.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_international_specific_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_specific_ABP.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_specific_block.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_specific_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_specific_uBO.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_thirdparty.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_allowlist.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_general_block.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_general_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_specific_block.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_specific_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_specific_uBO.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_thirdparty.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_ai_suggestions.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_allowlist.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_allowlist_general_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_general_block.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_general_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_international.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_specific_ABP.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_specific_block.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_specific_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_specific_uBO.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_thirdparty.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_antifonts.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_chatapps_third-party.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_allowlist.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_allowlist_general_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_general_block.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_general_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_international_block.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_international_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_shopping_allowlist.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_shopping_allowlist_general_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_shopping_specific_ABP.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_shopping_specific_block.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_shopping_specific_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_shopping_specific_uBO.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_specific_ABP.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_specific_block.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_specific_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_specific_uBO.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_thirdparty.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_allowlist.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_allowlist_general_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_general_block.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_general_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_specific_ABP.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_specific_block.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_specific_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_specific_uBO.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_thirdparty.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_allowlist.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_allowlist_general_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_general_block.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_general_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_international.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_specific_ABP.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_specific_block.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_specific_hide.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_specific_uBO.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_thirdparty.txt",
		"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_sounds_thirdparty.txt",
		"https://raw.githubusercontent.com/easylist/antiadblockfilters/master/antiadblockfilters/antiadblock_chinese.txt",
		"https://raw.githubusercontent.com/easylist/antiadblockfilters/master/antiadblockfilters/antiadblock_english.txt",
		"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers.txt",
		"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers_firstparty.txt",
		"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/allowlist.txt",
		"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/allowlist_stealth.txt",
		"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/banner_sizes.txt",
		"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/content_blocker.txt",
		"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/cryptominers.txt",
		"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/general_elemhide.txt",
		"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/general_url.txt",
		"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/replace.txt",
		"https://adguardteam.github.io/AdguardFilters/ChineseFilter/sections/adservers.txt",
		"https://adguardteam.github.io/AdguardFilters/ChineseFilter/sections/adservers_firstparty.txt",
		"https://adguardteam.github.io/AdguardFilters/ChineseFilter/sections/allowlist.txt",
		"https://adguardteam.github.io/AdguardFilters/ChineseFilter/sections/antiadblock.txt",
		"https://adguardteam.github.io/AdguardFilters/ChineseFilter/sections/general_elemhide.txt",
		"https://adguardteam.github.io/AdguardFilters/ChineseFilter/sections/general_extensions.txt",
		"https://adguardteam.github.io/AdguardFilters/ChineseFilter/sections/general_url.txt",
		"https://adguardteam.github.io/AdguardFilters/ChineseFilter/sections/replace.txt",
		"https://adguardteam.github.io/AdguardFilters/ChineseFilter/sections/specific.txt",
		"https://adguardteam.github.io/AdguardFilters/MailTrackingFilter/sections/allowlist.txt",
		"https://adguardteam.github.io/AdguardFilters/MailTrackingFilter/sections/general_url.txt",
		"https://adguardteam.github.io/AdguardFilters/MailTrackingFilter/sections/specific.txt",
		"https://adguardteam.github.io/AdguardFilters/AnnoyancesFilter/Cookies/sections/cookies_allowlist.txt",
		"https://adguardteam.github.io/AdguardFilters/AnnoyancesFilter/Cookies/sections/cookies_general.txt",
		"https://adguardteam.github.io/AdguardFilters/AnnoyancesFilter/MobileApp/sections/mobile-app_allowlist.txt",
		"https://adguardteam.github.io/AdguardFilters/AnnoyancesFilter/MobileApp/sections/mobile-app_general.txt",
		"https://adguardteam.github.io/AdguardFilters/AnnoyancesFilter/Other/sections/annoyances.txt",
		"https://adguardteam.github.io/AdguardFilters/AnnoyancesFilter/Other/sections/tweaks.txt",
		"https://adguardteam.github.io/AdguardFilters/AnnoyancesFilter/Popups/sections/antiadblock.txt",
		"https://adguardteam.github.io/AdguardFilters/AnnoyancesFilter/Popups/sections/popups_allowlist.txt",
		"https://adguardteam.github.io/AdguardFilters/AnnoyancesFilter/Popups/sections/popups_general.txt",
		"https://adguardteam.github.io/AdguardFilters/AnnoyancesFilter/Popups/sections/push-notifications_allowlist.txt",
		"https://adguardteam.github.io/AdguardFilters/AnnoyancesFilter/Popups/sections/push-notifications_general.txt",
		"https://adguardteam.github.io/AdguardFilters/AnnoyancesFilter/Popups/sections/push-notifications_specific.txt",
		"https://adguardteam.github.io/AdguardFilters/AnnoyancesFilter/Popups/sections/subscriptions_allowlist.txt",
		"https://adguardteam.github.io/AdguardFilters/AnnoyancesFilter/Popups/sections/subscriptions_general.txt",
		"https://adguardteam.github.io/AdguardFilters/AnnoyancesFilter/Widgets/sections/widgets.txt",
		"https://adguardteam.github.io/AdguardFilters/MobileFilter/sections/adservers.txt",
		"https://adguardteam.github.io/AdguardFilters/MobileFilter/sections/allowlist_app.txt",
		"https://adguardteam.github.io/AdguardFilters/MobileFilter/sections/allowlist_web.txt",
		"https://adguardteam.github.io/AdguardFilters/MobileFilter/sections/antiadblock.txt",
		"https://adguardteam.github.io/AdguardFilters/MobileFilter/sections/general_elemhide.txt",
		"https://adguardteam.github.io/AdguardFilters/MobileFilter/sections/general_extensions.txt",
		"https://adguardteam.github.io/AdguardFilters/MobileFilter/sections/general_url.txt",
		"https://adguardteam.github.io/AdguardFilters/MobileFilter/sections/replace.txt",
		"https://adguardteam.github.io/AdguardFilters/MobileFilter/sections/specific_app.txt",
		"https://adguardteam.github.io/AdguardFilters/SocialFilter/sections/allowlist.txt",
		"https://adguardteam.github.io/AdguardFilters/SocialFilter/sections/general_elemhide.txt",
		"https://adguardteam.github.io/AdguardFilters/SocialFilter/sections/general_extensions.txt",
		"https://adguardteam.github.io/AdguardFilters/SocialFilter/sections/general_url.txt",
		"https://adguardteam.github.io/AdguardFilters/SocialFilter/sections/popups.txt",
		"https://adguardteam.github.io/AdguardFilters/SocialFilter/sections/social_trackers.txt",
		"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/allowlist.txt",
		"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/cookies_allowlist.txt",
		"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/cookies_general.txt",
		"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/cookies_specific.txt",
		"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/general_elemhide.txt",
		"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/general_extensions.txt",
		"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/general_url.txt",
		"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/mobile.txt",
		"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/mobile_allowlist.txt",
		"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/specific.txt",
		"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/tracking_servers.txt",
		"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/tracking_servers_firstparty.txt",
		"https://adguardteam.github.io/AdguardFilters/TrackParamFilter/sections/allowlist.txt",
		"https://adguardteam.github.io/AdguardFilters/TrackParamFilter/sections/general_url.txt",
		"https://adguardteam.github.io/AdguardFilters/TrackParamFilter/sections/specific.txt",
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
		"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_25_Mail_Tracking_Protection/filter.txt",
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
		"https://filters.adtidy.org/extension/chromium/filters/2.txt",
		"https://filters.adtidy.org/extension/chromium/filters/3.txt",
		"https://filters.adtidy.org/extension/chromium/filters/4.txt",
		"https://filters.adtidy.org/extension/chromium/filters/11.txt",
		"https://filters.adtidy.org/extension/chromium/filters/14.txt",
		"https://filters.adtidy.org/extension/chromium/filters/15.txt",
		"https://filters.adtidy.org/extension/chromium/filters/17.txt",
		"https://filters.adtidy.org/extension/chromium/filters/18.txt",
		"https://filters.adtidy.org/extension/chromium/filters/19.txt",
		"https://filters.adtidy.org/extension/chromium/filters/20.txt",
		"https://filters.adtidy.org/extension/chromium/filters/21.txt",
		"https://filters.adtidy.org/extension/chromium/filters/22.txt",
		"https://filters.adtidy.org/extension/chromium/filters/25.txt",
		"https://filters.adtidy.org/extension/firefox/filters/2.txt",
		"https://filters.adtidy.org/extension/firefox/filters/3.txt",
		"https://filters.adtidy.org/extension/firefox/filters/4.txt",
		"https://filters.adtidy.org/extension/firefox/filters/11.txt",
		"https://filters.adtidy.org/extension/firefox/filters/14.txt",
		"https://filters.adtidy.org/extension/firefox/filters/15.txt",
		"https://filters.adtidy.org/extension/firefox/filters/17.txt",
		"https://filters.adtidy.org/extension/firefox/filters/18.txt",
		"https://filters.adtidy.org/extension/firefox/filters/19.txt",
		"https://filters.adtidy.org/extension/firefox/filters/20.txt",
		"https://filters.adtidy.org/extension/firefox/filters/21.txt",
		"https://filters.adtidy.org/extension/firefox/filters/22.txt",
		"https://filters.adtidy.org/extension/firefox/filters/25.txt",
		"https://filters.adtidy.org/extension/ublock/filters/2.txt",
		"https://filters.adtidy.org/extension/ublock/filters/3.txt",
		"https://filters.adtidy.org/extension/ublock/filters/4.txt",
		"https://filters.adtidy.org/extension/ublock/filters/11.txt",
		"https://filters.adtidy.org/extension/ublock/filters/14.txt",
		"https://filters.adtidy.org/extension/ublock/filters/15.txt",
		"https://filters.adtidy.org/extension/ublock/filters/17.txt",
		"https://filters.adtidy.org/extension/ublock/filters/18.txt",
		"https://filters.adtidy.org/extension/ublock/filters/19.txt",
		"https://filters.adtidy.org/extension/ublock/filters/20.txt",
		"https://filters.adtidy.org/extension/ublock/filters/21.txt",
		"https://filters.adtidy.org/extension/ublock/filters/22.txt",
		"https://filters.adtidy.org/extension/ublock/filters/25.txt",
		"https://filters.adtidy.org/android/filters/2_optimized.txt",
		"https://filters.adtidy.org/android/filters/3_optimized.txt",
		"https://filters.adtidy.org/android/filters/4_optimized.txt",
		"https://filters.adtidy.org/android/filters/11_optimized.txt",
		"https://filters.adtidy.org/android/filters/14_optimized.txt",
		"https://filters.adtidy.org/android/filters/15_optimized.txt",
		"https://filters.adtidy.org/android/filters/17_optimized.txt",
		"https://filters.adtidy.org/android/filters/18_optimized.txt",
		"https://filters.adtidy.org/android/filters/19_optimized.txt",
		"https://filters.adtidy.org/android/filters/20_optimized.txt",
		"https://filters.adtidy.org/android/filters/21_optimized.txt",
		"https://filters.adtidy.org/android/filters/22_optimized.txt",
		"https://filters.adtidy.org/android/filters/25_optimized.txt",
		"https://filters.adtidy.org/ios/filters/2_optimized.txt",
		"https://filters.adtidy.org/ios/filters/3_optimized.txt",
		"https://filters.adtidy.org/ios/filters/4_optimized.txt",
		"https://filters.adtidy.org/ios/filters/11_optimized.txt",
		"https://filters.adtidy.org/ios/filters/14_optimized.txt",
		"https://filters.adtidy.org/ios/filters/15_optimized.txt",
		"https://filters.adtidy.org/ios/filters/18_optimized.txt",
		"https://filters.adtidy.org/ios/filters/19_optimized.txt",
		"https://filters.adtidy.org/ios/filters/20_optimized.txt",
		"https://filters.adtidy.org/ios/filters/21_optimized.txt",
		"https://filters.adtidy.org/ios/filters/22_optimized.txt",
		"https://filters.adtidy.org/ios/filters/25_optimized.txt",
		"https://ublockorigin.github.io/uAssets/filters/filters.min.txt",
		"https://ublockorigin.github.io/uAssets/filters/privacy.min.txt",
		"https://ublockorigin.github.io/uAssets/filters/badware.txt",
		"https://ublockorigin.github.io/uAssets/filters/quick-fixes.txt",
		"https://ublockorigin.github.io/uAssets/filters/unbreak.txt",
		"https://ublockorigin.github.io/uAssets/filters/annoyances.txt",
		"https://ublockorigin.github.io/uAssets/thirdparties/easylist.txt",
		"https://ublockorigin.github.io/uAssets/thirdparties/easyprivacy.txt",
		"https://ublockorigin.github.io/uAssets/thirdparties/easylist-annoyances.txt",
		"https://ublockorigin.github.io/uAssets/thirdparties/easylist-cookies.txt",
		"https://ublockorigin.github.io/uAssets/thirdparties/easylist-social.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-general.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-mobile.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy-removeparam.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-cookies.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-others.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/legacy.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/ubol-filters.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/ubo-link-shorteners.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easyprivacy.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-ai.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-annoyances.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-chat.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-cookies.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-newsletters.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-notifications.txt",
		"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-social.txt",
		"https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt",
		"https://malware-filter.gitlab.io/malware-filter/phishing-filter-ag.txt",
		"https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt",
		"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt",
		"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt",
		"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-online.txt",
		"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter.txt",
		"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag-online.txt",
		"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag.txt",
		"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh-online.txt",
		"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt",
		"https://malware-filter.gitlab.io/malware-filter/botnet-filter.txt",
		"https://malware-filter.gitlab.io/malware-filter/botnet-filter-ag.txt",
		"https://malware-filter.gitlab.io/malware-filter/botnet-filter-agh.txt",
		"https://malware-filter.gitlab.io/malware-filter/tracking-filter.txt"
)


# 仅处理能够转换为域名级拦截的修饰符；未知修饰符或带有上下文条件的修饰符均保守跳过。
# 使用完整规则身份处理 badfilter 撤销，避免误删同一域名下的其他规则。
function Get-RuleIdentity([string]$pattern, [string]$modifierString, [bool]$isWhitelistSource = $false) {
    if ([string]::IsNullOrWhiteSpace($pattern)) { return $null }

    $normalized = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($modifierString)) {
        foreach ($token in ($modifierString -split ',')) {
            $item = $token.Trim().ToLowerInvariant()
            if (-not [string]::IsNullOrWhiteSpace($item) -and $item -ne 'badfilter') {
                $normalized.Add($item)
            }
        }
    }

    $items = $normalized.ToArray()
    [System.Array]::Sort($items, [System.StringComparer]::Ordinal)
    $sourceClass = if ($isWhitelistSource) { 'ALLOWLIST-SOURCE' } else { 'FILTER-SOURCE' }
    return ($sourceClass + '|' + $pattern.Trim().ToLowerInvariant() + '$' + ($items -join ','))
}

function Resolve-Modifiers([string]$modStr) {
    $ret = [PSCustomObject]@{
        Decision    = "CONTINUE"
        SkipReason  = $null
        IsImportant = $false
    }
    if ([string]::IsNullOrWhiteSpace($modStr)) { return $ret }

    foreach ($mod in ($modStr -split ',' | ForEach-Object { $_.Trim().ToLowerInvariant() })) {
        if ([string]::IsNullOrWhiteSpace($mod)) { continue }

        $parts = $mod -split '=', 2
        $modName = $parts[0]

        # $all 会扩展到弹窗、文档和内联资源；$reason 依赖 $document，二者都不属于纯域名拦截语义。
        if ($modName -eq 'important') {
            $ret.IsImportant = $true
            continue
        }

        if ($modName -eq 'dnsrewrite') {
            $rv = if ($parts.Count -gt 1) { $parts[1].Trim().ToLowerInvariant() } else { '' }
            # 仅将明确指向 DNS 黑洞的响应视为拦截；真实 IP 地址、CNAME 和其他响应均不能转换为 REJECT。
            $isDnsBlock = (
                $rv -eq 'nxdomain' -or
                $rv -match '^noerror;a;(0\.0\.0\.0|127\.0\.0\.1)$' -or
                $rv -match '^noerror;aaaa;(::|::1|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$'
            )
            if ($isDnsBlock) { continue }
            $ret.Decision = "SKIP"
            $ret.SkipReason = "dnsrewrite-non-block:$rv"
            return $ret
        }

        $ret.Decision = "SKIP"
        $ret.SkipReason = "unsupported-modifier:$modName"
        return $ret
    }

    if ($ret.IsImportant) { $ret.Decision = "IMPORTANT_CONTINUE" }
    return $ret
}

function Is-ContextConstrainedWhitelist([string]$modStr) {
    if ([string]::IsNullOrWhiteSpace($modStr)) { return $false }
    foreach ($mod in ($modStr -split ',' | ForEach-Object { $_.Trim().ToLowerInvariant() })) {
        $name = ($mod -split '=', 2)[0]
        if ($name -ne 'important') { return $true }
    }
    return $false
}

function Get-WhitelistImportantFlag([string]$modStr) {
    if ([string]::IsNullOrWhiteSpace($modStr)) { return $false }
    foreach ($mod in ($modStr -split ',' | ForEach-Object { $_.Trim().ToLowerInvariant() })) {
        if ($mod -eq 'important') { return $true }
    }
    return $false
}

function Is-WhitelistSource([string]$url) {
    return $url -match "(?i)allowlist|exclusions|exceptions|whitelist"
}

# ── 辅助函数 ───────────────────────────────────────────────
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



# ── 统一规则解析函数 ───────────────────────────────────────
function Parse-Rule {
    param([string]$line, [bool]$isWhitelistSource = $false)

    $result = [PSCustomObject]@{
        Action       = "SKIP"
        Domain       = $null
        SkipReason   = "unmatched"
        SourceFormat = "unknown"
        IsImportant  = $false
        IsWildcard   = $false
        RuleKey      = $null
        IsFilterRule = $false
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

    # 广告过滤例外规则：分别处理精确匹配（EXACT）与后缀匹配（SUFFIX）。
    if ($line.StartsWith("@@")) {
        if (
            $line -match '^@@\|\|([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)(.*)$'
        ) {
            $extractDomain = $Matches[1]
            $afterDomain = $Matches[5]
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            $modPartRaw = if ($dollarIdx -ge 0) { $afterDomain.Substring($dollarIdx + 1) } else { $null }

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            $patternText = if ($line.Contains('$')) { $line.Substring(0, $line.IndexOf('$')) } else { $line }
            if ($null -ne $modPartRaw -and $modPartRaw -match '(?i)(^|,)badfilter(,|$)') {
                $result.Action = "BADFILTER"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist-badfilter"
                $result.RuleKey = Get-RuleIdentity $patternText $modPartRaw $isWhitelistSource
                $result.IsFilterRule = $true
                return $result
            }
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
                return $result
            }

            $result.Action = "EXCLUDE"
            $result.Domain = $extractDomain
            # 白名单侧优先避免误杀：域名锚定例外按后缀白名单投影；只有结尾 | 明确限定地址结束时才按精确白名单处理。
            $result.SourceFormat = if ($beforeMods -match '\|') { "whitelist-exact" } else { "whitelist-suffix" }
            $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            $result.RuleKey = Get-RuleIdentity $patternText $modPartRaw $isWhitelistSource
            $result.IsFilterRule = $true
            return $result
        }
        elseif ($line -match '^@@\|([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)\|(\$(.+))?$') {
            $candidate = $Matches[1]
            $modStr = $Matches[6]
            $patternText = "@@|$candidate|"

            if ($null -ne $modStr -and $modStr -match '(?i)(^|,)badfilter(,|$)') {
                $result.Action = "BADFILTER"
                $result.Domain = $candidate
                $result.SourceFormat = "adblock-whitelist-badfilter"
                $result.RuleKey = Get-RuleIdentity $patternText $modStr $isWhitelistSource
                $result.IsFilterRule = $true
                return $result
            }
            if (Is-ContextConstrainedWhitelist $modStr) {
                $result.SkipReason = "whitelist-context-constrained"
                return $result
            }

            $result.Action = "EXCLUDE"
            $result.Domain = $candidate
            $result.SourceFormat = "whitelist-exact"
            $result.IsImportant = Get-WhitelistImportantFlag $modStr
            $result.RuleKey = Get-RuleIdentity $patternText $modStr $isWhitelistSource
            $result.IsFilterRule = $true
            return $result
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $result.Action = "EXCLUDE"
            $result.Domain = $Matches[1]
            $result.SourceFormat = "whitelist-plain"
            $result.RuleKey = Get-RuleIdentity ("whitelist-plain:" + $Matches[1]) "" $isWhitelistSource
            return $result
        }

        $result.SkipReason = "whitelist-unparseable"
        return $result
    }

    # 广告过滤语法中的精确主机锚定规则：|domain|。
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1]
        $modStr = $Matches[3]
        $patternText = "|$candidate|"

        if ($null -ne $modStr -and $modStr -match '(?i)(^|,)badfilter(,|$)') {
            $result.Action = "BADFILTER"
            $result.Domain = $candidate
            $result.SourceFormat = "adblock-exact-badfilter"
            $result.RuleKey = Get-RuleIdentity $patternText $modStr $isWhitelistSource
            $result.IsFilterRule = $true
            return $result
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
        $result.RuleKey = Get-RuleIdentity $patternText $modStr $isWhitelistSource
        $result.IsFilterRule = $true
        return $result
    }

    # 域名锚定规则：包含路径、查询参数或通配符的规则，不能简化为普通后缀匹配。
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1]
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')
        $restBeforeDollar = if ($dollarIndex -ge 0) { $rest.Substring(0, $dollarIndex) } else { $rest }
        $modStr = if ($dollarIndex -ge 0) { $rest.Substring($dollarIndex + 1) } else { $null }
        $patternText = "||$raw$restBeforeDollar"

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }
        if ($raw -match '\*') {
            $result.SkipReason = "unrepresentable-wildcard-domain"
            return $result
        }

        if ($null -ne $modStr -and $modStr -match '(?i)(^|,)badfilter(,|$)') {
            $result.Action = "BADFILTER"
            $result.Domain = $raw
            $result.SourceFormat = "adblock-suffix-badfilter"
            $result.RuleKey = Get-RuleIdentity $patternText $modStr $isWhitelistSource
            $result.IsFilterRule = $true
            return $result
        }

        $modResult = Resolve-Modifiers $modStr
        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }
        if ($raw -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        # 只有明确的 ^ 分隔符才能安全投影为 DOMAIN-SUFFIX。
        # 白名单例外按更宽的后缀范围豁免以降低误杀；阻止规则无 ^ 时则收窄为 DOMAIN，避免扩大拦截。
        $isDomainSuffix = ($restBeforeDollar -eq '^')
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = if ($isDomainSuffix) { "SUFFIX" } else { "EXACT" }
            $result.SourceFormat = if ($isDomainSuffix) { "adblock-suffix" } else { "adblock-domain-anchor-exact" }
        }

        $result.Domain = $raw
        $result.IsImportant = $modResult.IsImportant
        $result.RuleKey = Get-RuleIdentity $patternText $modStr $isWhitelistSource
        $result.IsFilterRule = $true
        return $result
    }

    # hosts 文件中的条目按精确主机名处理。
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2]
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
        $result.RuleKey = Get-RuleIdentity ("hosts:" + $domain) "" $isWhitelistSource
        return $result
    }

    # dnsmasq 的 address 指令仅在明确返回黑洞地址时，才视为后缀拦截规则。
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1]
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' { $isBlock = $true }
            '^0\.0\.0\.0$' { $isBlock = $true }
            '^127\.0\.0\.1$' { $isBlock = $true }
            '^(::|::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' { $isBlock = $true }
            default { $isBlock = $false }
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
        $result.RuleKey = Get-RuleIdentity ("dnsmasq-address:" + $domain) "" $isWhitelistSource
        return $result
    }

    # dnsmasq 的 server/local 指令用于 DNS 转发或本地权威解析，不等同于拒绝访问。
    if ($line -match '^(server|local)=/') {
        $result.SkipReason = "dnsmasq-routing-not-block"
        return $result
    }

    # 裸域名沿用项目原有约定，按精确匹配（EXACT）处理；其他语义由各来源的文件格式决定。
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        $domain = $Matches[1]
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
            $result.RuleKey = Get-RuleIdentity ("whitelist-plain:" + $domain) "" $isWhitelistSource
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
            $result.RuleKey = Get-RuleIdentity ("plain-domain:" + $domain) "" $isWhitelistSource
        }
        $result.Domain = $domain
        return $result
    }

    $result.SkipReason = "no-pattern-match"
    return $result
}

$logFilePath = "$PSScriptRoot/adblock_log.txt"
$badfilterCancelKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$parsedRulesByKey = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
$skipStats = [System.Collections.Generic.Dictionary[string,int]]::new()
$formatStats = [System.Collections.Generic.Dictionary[string,int]]::new()

# 并行下载阶段：保持来源 URL 的原始顺序，并逐项收集下载结果。
$httpClient = [System.Net.Http.HttpClient]::new()
$httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

$downloadTasks = $urlList | ForEach-Object {
    [PSCustomObject]@{ Url = $_; Task = $httpClient.GetStringAsync($_) }
}
$urlContents = $downloadTasks | ForEach-Object {
    $currentUrl = $_.Url
    $currentTask = $_.Task
    $content = $null
    try { $content = $currentTask.GetAwaiter().GetResult() }
    catch {
        Write-Host "下载 $currentUrl 时出错: $_"
        Add-Content -Path $logFilePath -Value "下载 $currentUrl 时出错: $_"
    }
    [PSCustomObject]@{ Url = $currentUrl; Content = $content }
}
$httpClient.Dispose()

# 第一遍仅解析规则并收集规则身份；badfilter 撤销规则可以出现在原规则之前或之后。
foreach ($item in $urlContents) {
    $url = $item.Url
    Write-Host "正在处理: $url"
    Add-Content -Path $logFilePath -Value "正在处理: $url"
    $isWhitelistSrc = Is-WhitelistSource $url

    try {
        if ($null -eq $item.Content) { throw "下载失败，已跳过" }
        foreach ($line in ($item.Content -split "\r?\n")) {
            $normalizedLine = $line.Trim().Trim([char]0xFEFF)
            $linesToParse = [System.Collections.Generic.List[string]]::new()
            $hostsMatch = [regex]::Match($normalizedLine, '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+(.+)$')
            if ($hostsMatch.Success) {
                $hostPart = ($hostsMatch.Groups[2].Value -split '\s+#', 2)[0]
                foreach ($hostName in ($hostPart -split '\s+')) {
                    if ($hostName -match '^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
                        $linesToParse.Add("$($hostsMatch.Groups[1].Value) $hostName")
                    }
                }
            }
            else {
                $linesToParse.Add($normalizedLine)
            }

            foreach ($candidateLine in $linesToParse) {
                $parsed = Parse-Rule $candidateLine -isWhitelistSource $isWhitelistSrc

                switch ($parsed.Action) {
                "BADFILTER" {
                    if (-not [string]::IsNullOrWhiteSpace($parsed.RuleKey)) {
                        $badfilterCancelKeys.Add($parsed.RuleKey) | Out-Null
                    }
                    else {
                        if (-not $skipStats.ContainsKey("badfilter-unparseable")) { $skipStats["badfilter-unparseable"] = 0 }
                        $skipStats["badfilter-unparseable"]++
                    }
                }
                "SKIP" {
                    if (-not $skipStats.ContainsKey($parsed.SkipReason)) { $skipStats[$parsed.SkipReason] = 0 }
                    $skipStats[$parsed.SkipReason]++
                }
                default {
                    if ($parsed.Action -in @("EXCLUDE", "SUFFIX", "EXACT")) {
                        $storeKey = "$($parsed.Action)|$($parsed.RuleKey)"
                        if (-not $parsedRulesByKey.ContainsKey($storeKey)) {
                            $parsedRulesByKey[$storeKey] = $parsed
                        }
                    }
                }
                }
            }
        }
    }
    catch {
        Write-Host "处理 $url 时出错: $_"
        Add-Content -Path $logFilePath -Value "处理 $url 时出错: $_"
    }
}

# 第二遍应用 badfilter 撤销结果，再分别构建互相独立的精确匹配与后缀匹配黑白名单集合。
$uniqueSuffixRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$uniqueExactRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$excludedExactDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$excludedSuffixDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$importantExactDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$importantSuffixDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$importantWhitelistExactDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$importantWhitelistSuffixDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($parsed in $parsedRulesByKey.Values) {
    if ($parsed.IsFilterRule -and $parsed.RuleKey -and $badfilterCancelKeys.Contains($parsed.RuleKey)) {
        if (-not $skipStats.ContainsKey("badfilter-cancelled")) { $skipStats["badfilter-cancelled"] = 0 }
        $skipStats["badfilter-cancelled"]++
        continue
    }

    $domain = Normalize-Domain $parsed.Domain
    if (-not (Is-ValidDNSDomain $domain)) {
        if (-not $skipStats.ContainsKey("invalid-domain")) { $skipStats["invalid-domain"] = 0 }
        $skipStats["invalid-domain"]++
        continue
    }
    if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
        if (-not $skipStats.ContainsKey("ip-address")) { $skipStats["ip-address"] = 0 }
        $skipStats["ip-address"]++
        continue
    }

    switch ($parsed.Action) {
        "EXCLUDE" {
            $isSuffixException = $parsed.SourceFormat -in @("whitelist-suffix", "whitelist-dnsmasq")
            if ($isSuffixException) {
                $excludedSuffixDomains.Add($domain) | Out-Null
                if ($parsed.IsImportant) { $importantWhitelistSuffixDomains.Add($domain) | Out-Null }
            }
            else {
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

    if (-not $formatStats.ContainsKey($parsed.SourceFormat)) { $formatStats[$parsed.SourceFormat] = 0 }
    $formatStats[$parsed.SourceFormat]++
}

# ── 过滤阶段 + 白名单抑制 + 冲突索引 + 父域冗余剪枝 ─────────────
$validSuffixRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$validExactRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# 匹配范围完全由上游规则决定；本脚本不会基于公共后缀列表（PSL）擅自改变匹配范围。
foreach ($d in $uniqueSuffixRules) {
    if (Is-ValidDNSDomain $d) { $validSuffixRules.Add($d) | Out-Null }
}
foreach ($d in $uniqueExactRules) {
    if (Is-ValidDNSDomain $d) { $validExactRules.Add($d) | Out-Null }
}

# 规则优先级遵循过滤规则的全局优先级，而不是“越具体的域名优先”：
# P0 重要白名单 > P1 重要黑名单 > P2 普通白名单 > P3 普通黑名单。
# 每个优先级都先检查当前域名及其所有父级后缀；DOMAIN 仅匹配当前域名，SUFFIX 匹配当前域名及其子域。
function Get-EffectiveStatus([string]$domain) {
    $domain = Normalize-Domain $domain
    if ([string]::IsNullOrWhiteSpace($domain)) { return "UNKNOWN" }
    $labels = $domain -split '\.'

    # P0：任何匹配当前请求的 $important 白名单，均优先于重要/普通黑名单。
    $current = $domain
    for ($i = 0; $i -lt $labels.Length - 1; $i++) {
        $current = ($labels[$i..($labels.Length-1)] -join '.')
        if ($i -eq 0 -and $importantWhitelistExactDomains.Contains($current)) { return "WHITELIST_P0" }
        if ($importantWhitelistSuffixDomains.Contains($current)) { return "WHITELIST_P0" }
    }

    # P1：重要黑名单优先于所有普通白名单及普通黑名单。
    $current = $domain
    for ($i = 0; $i -lt $labels.Length - 1; $i++) {
        $current = ($labels[$i..($labels.Length-1)] -join '.')
        if ($i -eq 0 -and $importantExactDomains.Contains($current)) { return "BLACKLIST_P1" }
        if ($importantSuffixDomains.Contains($current)) { return "BLACKLIST_P1" }
    }

    # P2：普通白名单对所有匹配同一请求的普通黑名单生效，不受域名层级深浅影响。
    $current = $domain
    for ($i = 0; $i -lt $labels.Length - 1; $i++) {
        $current = ($labels[$i..($labels.Length-1)] -join '.')
        if ($i -eq 0 -and $excludedExactDomains.Contains($current)) { return "WHITELIST_P2" }
        if ($excludedSuffixDomains.Contains($current)) { return "WHITELIST_P2" }
    }

    # P3：不存在更高优先级的匹配白名单/重要规则时，任意普通黑名单匹配即拦截。
    $current = $domain
    for ($i = 0; $i -lt $labels.Length - 1; $i++) {
        $current = ($labels[$i..($labels.Length-1)] -join '.')
        if ($i -eq 0 -and $validExactRules.Contains($current)) { return "BLACKLIST_P3" }
        if ($validSuffixRules.Contains($current)) { return "BLACKLIST_P3" }
    }
    return "UNKNOWN"
}

# 判断一个后缀白名单是否对其一般子域有效。
# 故意忽略 EXACT 规则：精确黑/白名单只影响根域本身，不影响该后缀白名单对其他子域的作用。
function Get-SuffixEffectiveStatus([string]$domain) {
    $domain = Normalize-Domain $domain
    if ([string]::IsNullOrWhiteSpace($domain)) { return "UNKNOWN" }
    $labels = $domain -split '\.'

    # P0：重要后缀白名单。
    $current = $domain
    for ($i = 0; $i -lt $labels.Length - 1; $i++) {
        $current = ($labels[$i..($labels.Length-1)] -join '.')
        if ($importantWhitelistSuffixDomains.Contains($current)) { return "WHITELIST_P0" }
    }

    # P1：重要后缀黑名单。
    $current = $domain
    for ($i = 0; $i -lt $labels.Length - 1; $i++) {
        $current = ($labels[$i..($labels.Length-1)] -join '.')
        if ($importantSuffixDomains.Contains($current)) { return "BLACKLIST_P1" }
    }

    # P2：普通后缀白名单。
    $current = $domain
    for ($i = 0; $i -lt $labels.Length - 1; $i++) {
        $current = ($labels[$i..($labels.Length-1)] -join '.')
        if ($excludedSuffixDomains.Contains($current)) { return "WHITELIST_P2" }
    }

    # P3：普通后缀黑名单。
    $current = $domain
    for ($i = 0; $i -lt $labels.Length - 1; $i++) {
        $current = ($labels[$i..($labels.Length-1)] -join '.')
        if ($validSuffixRules.Contains($current)) { return "BLACKLIST_P3" }
    }
    return "UNKNOWN"
}

Write-Host "正在执行自动降级机制与冲突检测..."
$suffixConflictExactDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$sameDomainSuffixWhitelistConflicts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$suffixDowngradedDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# 方案 A：优先保证不误杀。精确白名单与后缀白名单分别判断，不能用根域的 EXACT 冲突结果推断其所有子域。
# 精确白名单只有在根域请求本身有效时，才使覆盖它的父级 SUFFIX 候选降级。
foreach ($w in $excludedExactDomains) {
    if ((Get-EffectiveStatus $w) -notlike "WHITELIST*") { continue }

    # 同域精确白名单只豁免根域；无法用 DOMAIN / DOMAIN-SUFFIX 表达“根域放行、全部子域继续拦截”。
    if ($validSuffixRules.Contains($w)) {
        $sameDomainSuffixWhitelistConflicts.Add($w) | Out-Null
        $suffixConflictExactDomains.Add($w) | Out-Null
    }

    foreach ($parent in (Get-ParentDomains $w)) {
        if ($validSuffixRules.Contains($parent)) {
            $suffixConflictExactDomains.Add($parent) | Out-Null
        }
    }
}

# 后缀白名单的根域可能被 EXACT 黑名单覆盖，但它仍可能对其他子域有效。
# 因此只用 suffix 规则判断其一般子域范围，忽略不继承的 EXACT 黑/白名单。
foreach ($w in $excludedSuffixDomains) {
    if ((Get-SuffixEffectiveStatus $w) -notlike "WHITELIST*") { continue }

    # 同域后缀白名单与后缀黑名单冲突时，禁止保留同域 SUFFIX；若根域另有更高优先级 EXACT 黑名单，最终仍可单独输出 DOMAIN。
    if ($validSuffixRules.Contains($w)) {
        $sameDomainSuffixWhitelistConflicts.Add($w) | Out-Null
        $suffixConflictExactDomains.Add($w) | Out-Null
    }

    foreach ($parent in (Get-ParentDomains $w)) {
        if ($validSuffixRules.Contains($parent)) {
            $suffixConflictExactDomains.Add($parent) | Out-Null
        }
    }
}
Write-Host "冲突检测完成：$($suffixConflictExactDomains.Count) 个父 SUFFIX 候选需检查降级；同域精确白名单冲突：$($sameDomainSuffixWhitelistConflicts.Count)"

$rawSuffixSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$rawExactSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$allBlacklists = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$allBlacklists.UnionWith($validSuffixRules)
$allBlacklists.UnionWith($validExactRules)

foreach ($d in $allBlacklists) {
    if ((Get-EffectiveStatus $d) -notlike "BLACKLIST*") { continue }
    if ($validSuffixRules.Contains($d) -and -not $suffixConflictExactDomains.Contains($d)) {
        $rawSuffixSet.Add($d) | Out-Null
    }
    else {
        $rawExactSet.Add($d) | Out-Null
        if ($validSuffixRules.Contains($d) -and $suffixConflictExactDomains.Contains($d)) {
            $suffixDowngradedDomains.Add($d) | Out-Null
        }
    }
}

# ── 冲突子树域名树补全 ───────────────────────────────────────────────────────
# DOMAIN-SUFFIX 无法表达“父域拦截、特定子域放行”的负向例外。
# 对发生白名单冲突的后缀根建立域名树，只遍历上游已知的黑名单/白名单节点。
# 冲突子树内仍有效的黑名单候选统一收窄为 DOMAIN；白名单节点和仅用于连接树的中间节点绝不输出。
$domainTreeRoots = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($candidate in $suffixConflictExactDomains) {
    if (-not $validSuffixRules.Contains($candidate)) { continue }

    # 只从最上层冲突后缀开始遍历，避免嵌套冲突根重复扫描。
    $hasConflictAncestor = $false
    foreach ($parent in (Get-ParentDomains $candidate)) {
        if ($validSuffixRules.Contains($parent) -and $suffixConflictExactDomains.Contains($parent)) {
            $hasConflictAncestor = $true
            break
        }
    }
    if (-not $hasConflictAncestor) { $domainTreeRoots.Add($candidate) | Out-Null }
}

$domainTreeCompletedDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$domainTreeSuffixPreferredDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
if ($domainTreeRoots.Count -gt 0) {
    # 规则域名与白名单域名均进入索引；所有父域节点补齐树路径，但中间节点不是输出候选。
    $domainTreeKnownDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $domainTreeKnownDomains.UnionWith($allBlacklists)
    $domainTreeKnownDomains.UnionWith($excludedExactDomains)
    $domainTreeKnownDomains.UnionWith($excludedSuffixDomains)

    $domainTreeNodes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($domain in $domainTreeKnownDomains) {
        $domainTreeNodes.Add($domain) | Out-Null
        foreach ($parent in (Get-ParentDomains $domain)) {
            $domainTreeNodes.Add($parent) | Out-Null
        }
    }

    # 键为父域，值为其直接子域节点；例如 example.com -> cdn.example.com。
    $domainTreeChildren = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[string]]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($domain in $domainTreeNodes) {
        $firstDot = $domain.IndexOf('.')
        if ($firstDot -lt 1) { continue }
        $parent = $domain.Substring($firstDot + 1)

        $children = $null
        if (-not $domainTreeChildren.TryGetValue($parent, [ref]$children)) {
            $children = [System.Collections.Generic.List[string]]::new()
            $domainTreeChildren[$parent] = $children
        }
        $children.Add($domain)
    }

    $script:domainTreeChildren = $domainTreeChildren
    $script:domainTreeAllBlacklists = $allBlacklists
    $script:domainTreeValidSuffixRules = $validSuffixRules
    $script:domainTreeValidExactRules = $validExactRules
    $script:domainTreeSuffixConflictExactDomains = $suffixConflictExactDomains
    $script:domainTreeRawSuffixSet = $rawSuffixSet
    $script:domainTreeRawExactSet = $rawExactSet
    $script:domainTreeCompletedDomains = $domainTreeCompletedDomains
    $script:domainTreeSuffixDowngradedDomains = $suffixDowngradedDomains
    $script:domainTreeSuffixPreferredDomains = $domainTreeSuffixPreferredDomains

    function Expand-DomainTreeBlacklist([string]$domain) {
        # 仅处理上游显式黑名单候选，且必须通过与主流程相同的优先级判定。
        if ($script:domainTreeAllBlacklists.Contains($domain) -and
            (Get-EffectiveStatus $domain) -like "BLACKLIST*") {

            if ($script:domainTreeValidSuffixRules.Contains($domain)) {
                # 同域 EXACT + SUFFIX 时优先保留 SUFFIX；但该节点自身存在有效白名单例外时必须收窄为 DOMAIN。
                $hasWhitelistBoundary = $script:domainTreeSuffixConflictExactDomains.Contains($domain)
                $hasExactDuplicate = $script:domainTreeValidExactRules.Contains($domain)

                if ($hasExactDuplicate -and -not $hasWhitelistBoundary) {
                    # 同域双类型候选优先 SUFFIX，消除较窄的 EXACT，保留上游更完整的匹配语义。
                    $wasExact = $script:domainTreeRawExactSet.Remove($domain)
                    $wasSuffix = $script:domainTreeRawSuffixSet.Add($domain)
                    $script:domainTreeSuffixDowngradedDomains.Remove($domain) | Out-Null
                    $script:domainTreeSuffixPreferredDomains.Add($domain) | Out-Null
                }
                else {
                    # 冲突节点或仅有 SUFFIX 的子节点均保守收窄为 DOMAIN，避免覆盖白名单及未知后代。
                    $wasSuffix = $script:domainTreeRawSuffixSet.Remove($domain)
                    $wasExact = $script:domainTreeRawExactSet.Add($domain)
                    $script:domainTreeSuffixDowngradedDomains.Add($domain) | Out-Null
                    if ($wasSuffix -or $wasExact) {
                        $script:domainTreeCompletedDomains.Add($domain) | Out-Null
                    }
                }
            }
            else {
                # 上游原本只有 EXACT：确保其保留为 DOMAIN。
                if ($script:domainTreeRawExactSet.Add($domain)) {
                    $script:domainTreeCompletedDomains.Add($domain) | Out-Null
                }
            }
        }

        $children = $null
        if ($script:domainTreeChildren.TryGetValue($domain, [ref]$children)) {
            foreach ($childDomain in $children) {
                Expand-DomainTreeBlacklist $childDomain
            }
        }
    }

    foreach ($root in ($domainTreeRoots | Sort-Object)) {
        Expand-DomainTreeBlacklist $root
    }
    Remove-Item Function:\Expand-DomainTreeBlacklist -ErrorAction SilentlyContinue
    Remove-Variable domainTreeChildren, domainTreeKnownDomains, domainTreeNodes, domainTreeRoots, domainTreeAllBlacklists, domainTreeValidSuffixRules, domainTreeRawSuffixSet, domainTreeRawExactSet, domainTreeSuffixDowngradedDomains, domainTreeValidExactRules, domainTreeSuffixConflictExactDomains -Scope Script -ErrorAction SilentlyContinue
}

Write-Host "域名树补全完成：新增/收窄 $($domainTreeCompletedDomains.Count) 条 DOMAIN；同域双类型优先 SUFFIX：$($domainTreeSuffixPreferredDomains.Count)"

# 仅删除已被有效父级后缀规则完全覆盖的规则；存在例外冲突的父域不参与跨层级剪枝。
Write-Host "正在执行语义安全的冗余剪枝..."
$classSuffixBlocks = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($d in $rawSuffixSet) {
    $covered = $false
    foreach ($parent in (Get-ParentDomains $d)) {
        if ($rawSuffixSet.Contains($parent)) { $covered = $true; break }
    }
    if (-not $covered) { $classSuffixBlocks.Add($d) | Out-Null }
}

$classExactBlocks = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($d in $rawExactSet) {
    $covered = $false
    foreach ($parent in (Get-ParentDomains $d)) {
        if ($classSuffixBlocks.Contains($parent)) { $covered = $true; break }
    }
    if (-not $covered) { $classExactBlocks.Add($d) | Out-Null }
}

$classWhitelist = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
# EXACT 白名单按根域实际状态统计；SUFFIX 白名单按一般子域作用范围统计，避免被根域 EXACT 冲突误判为无效。
foreach ($w in $excludedExactDomains) {
    if ((Get-EffectiveStatus $w) -like "WHITELIST*") { $classWhitelist.Add($w) | Out-Null }
}
foreach ($w in $excludedSuffixDomains) {
    if ((Get-SuffixEffectiveStatus $w) -like "WHITELIST*") { $classWhitelist.Add($w) | Out-Null }
}

Write-Host "规则集合构建完成：Whitelist $($classWhitelist.Count) | DOMAIN $($classExactBlocks.Count) | DOMAIN-SUFFIX $($classSuffixBlocks.Count)"
Write-Host "冲突子树内收窄为 DOMAIN：$($suffixDowngradedDomains.Count) | 域名树新增/收窄：$($domainTreeCompletedDomains.Count) | 同域精确白名单抑制后缀候选：$($sameDomainSuffixWhitelistConflicts.Count)"

# ── 输出 YAML 规则集 ───────────────────────────────
$ruleCount    = $classExactBlocks.Count + $classSuffixBlocks.Count
$generateTime = (Get-Date -AsUTC).AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

$allLines = [System.Collections.Generic.List[string]]::new()
$allLines.Add("# 标题：AdBlock_Rule_For_Clash")
$allLines.Add("# 说明：适用于 Clash 的域名拦截规则集，每 20 分钟更新一次，以同步上游规则")
$allLines.Add("# 项目主页：https://github.com/REIJI007/AdBlock_Rule_For_Clash")
$allLines.Add("# 开源协议 1：GPL-3.0")
$allLines.Add("# 开源协议 2：CC-BY-NC-SA 4.0")
$allLines.Add("# 生成时间：$generateTime")
$allLines.Add("# 规则总数：$ruleCount")
$allLines.Add("# 精确域名规则（DOMAIN）：$($classExactBlocks.Count)")
$allLines.Add("# 后缀域名规则（DOMAIN-SUFFIX）：$($classSuffixBlocks.Count)")
$allLines.Add("# 白名单规则数：$($classWhitelist.Count)")
$allLines.Add("")

$allLines.Add("payload:")
$allLines.Add("")

foreach ($d in ($classSuffixBlocks | Sort-Object)) {
    $allLines.Add("  - DOMAIN-SUFFIX,$d")
}

foreach ($d in ($classExactBlocks | Sort-Object)) {
    if ($suffixDowngradedDomains.Contains($d)) { $allLines.Add("  # [域名树保守补全] $($d)：冲突子树内收窄为精确域名；仅拦截上游明确列出的黑名单域名") }
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
Add-Content -Path $logFilePath -Value "Generated at $generateTime | Total: $ruleCount | DOMAIN: $($classExactBlocks.Count) | SUFFIX: $($classSuffixBlocks.Count) | Whitelist: $($classWhitelist.Count) | SuffixDowngraded: $($suffixDowngradedDomains.Count) | SameDomainWhitelistConflicts: $($sameDomainSuffixWhitelistConflicts.Count) | TreeCompleted: $($domainTreeCompletedDomains.Count) | SuffixPreferred: $($domainTreeSuffixPreferredDomains.Count) | Skipped: $totalSkipped"
Pause
