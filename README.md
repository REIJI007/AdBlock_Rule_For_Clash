<div align="center">

# AdBlock Rule For Clash

**适用于 Clash / Mihomo 的广告域名拦截规则集**

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)]
[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)]
[![Stars](https://img.shields.io/github/stars/REIJI007/AdBlock_Rule_For_Clash)]
[![Issues](https://img.shields.io/github/issues/REIJI007/AdBlock_Rule_For_Clash)]

</div>

## 订阅文件

| 格式 | 文件 | Provider 配置 |
| :---: | :--- | :--- |
| YAML | [adblock_reject.yaml](https://raw.githubusercontent.com/REIJI007/AdBlock_Rule_For_Clash/main/adblock_reject.yaml) | behavior: classical, format: yaml |
| TXT | [adblock_reject.txt](https://raw.githubusercontent.com/REIJI007/AdBlock_Rule_For_Clash/main/adblock_reject.txt) | behavior: classical, format: text |
| MRS | [adblock_reject.mrs](https://raw.githubusercontent.com/REIJI007/AdBlock_Rule_For_Clash/main/adblock_reject.mrs) | behavior: domain, format: mrs |

## 配置示例

~~~yaml
dns:
  enable: true
  nameserver-policy:
    'geosite:category-ads-all': rcode://success

rule-providers:
  adblock:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/REIJI007/AdBlock_Rule_For_Clash/main/adblock_reject.yaml
    path: ./ruleset/adblock_reject.yaml
    interval: 120
    timeout: 30

rules:
  - GEOSITE,category-ads-all,REJECT
  - RULE-SET,adblock,REJECT
~~~

TXT Provider 只需将 URL 和 path 指向 adblock_reject.txt，并设置 format: text。MRS 使用 behavior: domain、format: mrs。

## 规则语义与严格编译

- 上游白名单会参与内部优先级裁决，但不会进入 YAML、TXT 或 MRS 规则产物。
- Classical YAML/TXT 最终只包含 DOMAIN 和 DOMAIN-SUFFIX 两类黑名单规则。
- 引擎独立保留 EXACT / SUFFIX 匹配范围，并按 P0 重要白名单、P1 重要黑名单、P2 普通白名单、P3 普通精确黑名单、P4 普通后缀黑名单求值。
- $badfilter 按规范化规则身份撤销，不再按域名粗粒度删除。
- PSL 普通、通配和例外规则都会参与公共后缀计算；不会擅自把上游后缀规则改成精确规则。
- 当后缀黑名单与有效白名单形成部分交叉时，有限的正向 DOMAIN / DOMAIN-SUFFIX 集合无法表达该例外。默认严格模式会中止规则发布，保留上一次有效规则文件，并在构建报告中列出冲突。
- 可以使用 pwsh ./Build-AdblockRules.ps1 -AllowLossy 显式允许有损构建；这不是严格同步，不建议用于正式订阅。

## MRS 域名格式

MRS 使用 Mihomo 的 domain behavior，而不是 classical 规则表达式。生成的 domain YAML 使用 Clash 域名通配语义：

~~~yaml
payload:
  - "api.example.com"
  - "+.example.org"
~~~

普通域名条目表示精确主机名；+.example.org 这类加号点前缀表示包含根域名及所有子域的后缀匹配。Mihomo 文档说明，MRS 仅支持 domain / ipcidr behavior，必须使用 domain 格式输入转换。

## 上游来源与构建审计

- 317 个唯一上游来源集中维护于 config/upstream-sources.json，显式声明语法模式、默认动作、裸域名和 Hosts 记录的 EXACT / SUFFIX 解释、预处理类型、必需性、超时、最大字节数和重试次数。
- 默认动作及裸域名匹配类型初始迁移自旧版本的来源识别和处理行为（36 个 ALLOW 来源的裸域名初始设为 SUFFIX，其余设为 EXACT）。这些值已经成为逐来源可审查的显式配置，但尚不代表逐一完成了上游语义人工审计；合并前应重点复核 36 个 ALLOW 来源及裸域名 / Hosts 列表的匹配约定。
- 下载清单及 SHA-256 写入 adblock_sources_manifest.json；规则数量、撤销数、范围外语法及白名单冲突写入 adblock_build_report.json。
- 必需来源下载失败时构建失败。uBO 的静态 !#include 会递归展开；需要运行环境判断的 !#if 条件指令无法由通用 DNS 编译器推断，严格模式会停止发布而不是猜测分支。
- 无法无损转换的 URL 路径、请求类型、通配符及其他非 DNS 规则会标记为范围外规则，不会扩大成整个域名拦截。

## 测试

在 PowerShell 7 环境运行：

~~~powershell
pwsh -NoProfile -File ./tests/Run-Tests.ps1
~~~

GitHub Actions 会在 Pull Request 中运行规则引擎回归测试和来源配置验证。
