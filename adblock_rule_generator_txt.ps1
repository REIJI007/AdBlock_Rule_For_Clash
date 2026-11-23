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
"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/cryptominers.txt",
"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/foreign.txt",
"https://adguardteam.github.io/AdguardFilters/ChineseFilter/sections/adservers.txt",
"https://adguardteam.github.io/AdguardFilters/ChineseFilter/sections/adservers_firstparty.txt",
"https://adguardteam.github.io/AdguardFilters/MobileFilter/sections/adservers.txt",
"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/mobile.txt",
"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/tracking_servers.txt",
"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/tracking_servers_firstparty.txt",
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
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_259_Dandelion_Sprout's_Anti-Malware_List/filter.txt",
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


# 只接受能够投影为域名级拦截的修饰符；未知或带上下文条件的修饰符一律保守跳过。
# badfilter 使用规则身份而非域名撤销，避免误删同域的其他规则。
function Get-RuleIdentity([string]$pattern, [string]$modifierString) {
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
    return ($pattern.Trim().ToLowerInvariant() + '$' + ($items -join ','))
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

        if ($modName -eq 'important') {
            $ret.IsImportant = $true
            continue
        }

        if ($modName -eq 'dnsrewrite') {
            $rv = if ($parts.Count -gt 1) { $parts[1].Trim().ToLowerInvariant() } else { '' }
            # 仅将明确的 DNS 黑洞响应视为拦截；真实地址、CNAME 和其他响应不能变成 REJECT。
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

$modAllowSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@('all','document','doc','reason') | ForEach-Object { $modAllowSet.Add($_) | Out-Null }

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
        if ($mod -ne 'important') { return $true }
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

    # Adblock 例外规则：分离 EXACT 与 SUFFIX。
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
                $result.RuleKey = Get-RuleIdentity $patternText $modPartRaw
                $result.IsFilterRule = $true
                return $result
            }
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
                return $result
            }

            $result.Action = "EXCLUDE"
            $result.Domain = $extractDomain
            $result.SourceFormat = if ($beforeMods -match '\|') { "whitelist-exact" } else { "whitelist-suffix" }
            $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            $result.RuleKey = Get-RuleIdentity $patternText $modPartRaw
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
                $result.RuleKey = Get-RuleIdentity $patternText $modStr
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
            $result.RuleKey = Get-RuleIdentity $patternText $modStr
            $result.IsFilterRule = $true
            return $result
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $result.Action = "EXCLUDE"
            $result.Domain = $Matches[1]
            $result.SourceFormat = "whitelist-plain"
            $result.RuleKey = Get-RuleIdentity ("whitelist-plain:" + $Matches[1]) ""
            return $result
        }

        $result.SkipReason = "whitelist-unparseable"
        return $result
    }

    # Adblock 精确主机锚定规则：|domain|
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1]
        $modStr = $Matches[3]
        $patternText = "|$candidate|"

        if ($null -ne $modStr -and $modStr -match '(?i)(^|,)badfilter(,|$)') {
            $result.Action = "BADFILTER"
            $result.Domain = $candidate
            $result.SourceFormat = "adblock-exact-badfilter"
            $result.RuleKey = Get-RuleIdentity $patternText $modStr
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
        $result.RuleKey = Get-RuleIdentity $patternText $modStr
        $result.IsFilterRule = $true
        return $result
    }

    # 域名锚定规则：路径、查询和通配符不能降级成普通后缀。
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
            $result.RuleKey = Get-RuleIdentity $patternText $modStr
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

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $raw
        $result.IsImportant = $modResult.IsImportant
        $result.RuleKey = Get-RuleIdentity $patternText $modStr
        $result.IsFilterRule = $true
        return $result
    }

    # Hosts 条目按精确主机处理。
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
        $result.RuleKey = Get-RuleIdentity ("hosts:" + $domain) ""
        return $result
    }

    # dnsmasq address 只在明确返回黑洞地址时视为后缀拦截。
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
        $result.RuleKey = Get-RuleIdentity ("dnsmasq-address:" + $domain) ""
        return $result
    }

    # dnsmasq server/local 是 DNS 路由或本地权威行为，不等价于拒绝访问。
    if ($line -match '^(server|local)=/') {
        $result.SkipReason = "dnsmasq-routing-not-block"
        return $result
    }

    # 裸域名沿用项目原有约定：EXACT；具体来源的其他语义需由其文件格式定义。
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        $domain = $Matches[1]
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
            $result.RuleKey = Get-RuleIdentity ("whitelist-plain:" + $domain) ""
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
            $result.RuleKey = Get-RuleIdentity ("plain-domain:" + $domain) ""
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

# 并行下载阶段：保持 URL 顺序，逐项收集下载结果。
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

# 第一遍只解析并收集规则身份；badfilter 可以出现在原规则之前或之后。
foreach ($item in $urlContents) {
    $url = $item.Url
    Write-Host "正在处理: $url"
    Add-Content -Path $logFilePath -Value "正在处理: $url"
    $isWhitelistSrc = Is-WhitelistSource $url

    try {
        if ($null -eq $item.Content) { throw "下载失败，已跳过" }
        foreach ($line in ($item.Content -split "\r?\n")) {
            $normalizedLine = $line.Trim().Trim([char]0xFEFF)
            $parsed = Parse-Rule $normalizedLine -isWhitelistSource $isWhitelistSrc

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
    catch {
        Write-Host "处理 $url 时出错: $_"
        Add-Content -Path $logFilePath -Value "处理 $url 时出错: $_"
    }
}

# 第二遍应用 badfilter，再构建彼此独立的精确/后缀黑白名单集合。
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

# ── 过滤阶段 + 白名单抑制 + 冲突索引 + 父域剪枝 ─────────────
$validSuffixRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$validExactRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# 匹配粒度由上游规则决定；不能因为域名属于 PSL 就把 SUFFIX 改写成 EXACT。
foreach ($d in $uniqueSuffixRules) {
    if (Is-ValidDNSDomain $d) { $validSuffixRules.Add($d) | Out-Null }
}
foreach ($d in $uniqueExactRules) {
    if (Is-ValidDNSDomain $d) { $validExactRules.Add($d) | Out-Null }
}

# 保留项目现有的优先级策略，同时严格区分 EXACT 与 SUFFIX 的继承范围。
function Get-EffectiveStatus([string]$domain) {
    $domain = Normalize-Domain $domain
    if ([string]::IsNullOrWhiteSpace($domain)) { return "UNKNOWN" }
    $labels = $domain -split '\.'

    # P0：重要白名单。精确例外不向子域继承，后缀例外向子域继承。
    $current = $domain
    for ($i = 0; $i -lt $labels.Length - 1; $i++) {
        $current = ($labels[$i..($labels.Length-1)] -join '.')
        if ($i -eq 0 -and $importantWhitelistExactDomains.Contains($current)) { return "WHITELIST_P0" }
        if ($importantWhitelistSuffixDomains.Contains($current)) { return "WHITELIST_P0" }
    }

    # P1：重要黑名单。重要精确规则只匹配当前主机，重要后缀规则向下继承。
    $current = $domain
    for ($i = 0; $i -lt $labels.Length - 1; $i++) {
        $current = ($labels[$i..($labels.Length-1)] -join '.')
        if ($i -eq 0 -and $importantExactDomains.Contains($current)) { return "BLACKLIST_P1" }
        if ($importantSuffixDomains.Contains($current)) { return "BLACKLIST_P1" }
    }

    # P2-P4：最近层级优先，同一层级先判断例外，再判断拦截。
    $current = $domain
    for ($i = 0; $i -lt $labels.Length - 1; $i++) {
        $current = ($labels[$i..($labels.Length-1)] -join '.')
        if ($i -eq 0 -and $excludedExactDomains.Contains($current)) { return "WHITELIST_P2" }
        if ($excludedSuffixDomains.Contains($current)) { return "WHITELIST_P2" }
        if ($i -eq 0 -and $validExactRules.Contains($current)) { return "BLACKLIST_P3" }
        if ($validSuffixRules.Contains($current)) { return "BLACKLIST_P4" }
    }
    return "UNKNOWN"
}

Write-Host "正在执行自动降级机制与冲突检测..."
$suffixConflictExactDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$allWhitelists = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$allWhitelists.UnionWith($excludedExactDomains)
$allWhitelists.UnionWith($excludedSuffixDomains)
$allWhitelists.UnionWith($importantWhitelistExactDomains)
$allWhitelists.UnionWith($importantWhitelistSuffixDomains)

# 后缀黑名单内部存在有效例外时，纯正向域名规则无法完整表达该排除区域。
# 父后缀降级为 DOMAIN 只保留父域本身；其他明确有效的子域规则仍按自身类型输出。
foreach ($w in $allWhitelists) {
    if ((Get-EffectiveStatus $w) -notlike "WHITELIST*") { continue }

    # 同域 EXACT 白名单只豁免 Apex，但后缀黑名单仍可能覆盖其子域。
    if (
        $validSuffixRules.Contains($w) -and
        ($excludedExactDomains.Contains($w) -or $importantWhitelistExactDomains.Contains($w))
    ) {
        $suffixConflictExactDomains.Add($w) | Out-Null
    }

    foreach ($parent in (Get-ParentDomains $w)) {
        if ($validSuffixRules.Contains($parent) -and (Get-EffectiveStatus $parent) -like "BLACKLIST*") {
            $suffixConflictExactDomains.Add($parent) | Out-Null
        }
    }
}
Write-Host "冲突检测完成，共有 $($suffixConflictExactDomains.Count) 个 SUFFIX 规则无法无损表达，将按 DOMAIN 近似保留"

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
    }
}

# 只删除被有效父后缀完全覆盖的规则；不跨越存在例外冲突的父域做剪枝。
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
foreach ($w in $allWhitelists) {
    if ((Get-EffectiveStatus $w) -like "WHITELIST*") { $classWhitelist.Add($w) | Out-Null }
}

Write-Host "三类集合构建完成：Whitelist $($classWhitelist.Count) | DOMAIN $($classExactBlocks.Count) | DOMAIN-SUFFIX $($classSuffixBlocks.Count)"

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
$allLines.Add("# Semantic Warning : $($suffixConflictExactDomains.Count) suffix rules narrowed to DOMAIN; positive domain rules cannot encode descendant exceptions")
$allLines.Add("")

$allLines.Add("payload:")
$allLines.Add("")

foreach ($d in ($classSuffixBlocks | Sort-Object)) {
    $allLines.Add("  - DOMAIN-SUFFIX,$d")
}

foreach ($d in ($classExactBlocks | Sort-Object)) {
    if ($suffixConflictExactDomains.Contains($d)) { $allLines.Add("  # [SEMANTIC-LOSS] $d: suffix scope narrowed to exact due to an exception") }
    $allLines.Add("  - DOMAIN,$d")
}

$outputPath = "$PSScriptRoot/adblock_reject.txt"
($allLines -join "`n") | Out-File -FilePath $outputPath -Encoding utf8

# ── 控制台诊断输出 ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "===== 生成完成 ====="
Write-Host "生成时间: $generateTime"
Write-Host "总规则数: $ruleCount (DOMAIN: $($classExactBlocks.Count) | DOMAIN-SUFFIX: $($classSuffixBlocks.Count))"
Write-Host "白名单放行: $($classWhitelist.Count)"
Write-Host "后缀例外冲突降级数: $($suffixConflictExactDomains.Count)（仅保留可表达的精确范围）"
Write-Host "提示: DOMAIN / DOMAIN-SUFFIX 只能表达正向域名集合，无法完整表示父后缀内的子域例外"
Write-Host "文件路径: $outputPath"
Write-Host "=== 文件前 20 行预览 ==="
Get-Content -Path $outputPath -TotalCount 20 | ForEach-Object { Write-Host $_ }

$totalSkipped = ($skipStats.Values | Measure-Object -Sum).Sum
Add-Content -Path $logFilePath -Value "Generated at $generateTime | Total: $ruleCount | DOMAIN: $($classExactBlocks.Count) | SUFFIX: $($classSuffixBlocks.Count) | Whitelist: $($classWhitelist.Count) | SuffixConflicts: $($suffixConflictExactDomains.Count) | Skipped: $totalSkipped"
Pause
