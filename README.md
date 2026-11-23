<div align="center">

# AdBlock Rule For Clash

**适用于 Clash 的广告域名拦截规则集**

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)]
[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)]
[![Last Commit](https://img.shields.io/badge/last%20commit-today-brightgreen)]
[![Stars](https://img.shields.io/github/stars/REIJI007/AdBlock_Rule_For_Clash)]
[![Issues](https://img.shields.io/github/issues/REIJI007/AdBlock_Rule_For_Clash)]

</div>

## 订阅链接

选择所需的规则格式，点击链接即可获取对应的订阅文件。

| 格式 | 订阅文件 | 订阅地址 |
| :---: | :--- | :---: |
| **YAML** | `adblock_reject.yaml` | [获取订阅 ↗](https://raw.githubusercontent.com/REIJI007/AdBlock_Rule_For_Clash/main/adblock_reject.yaml) |
| **MRS** | `adblock_reject.mrs` | [获取订阅 ↗](https://raw.githubusercontent.com/REIJI007/AdBlock_Rule_For_Clash/main/adblock_reject.mrs) |
| **TXT** | `adblock_reject.txt` | [获取订阅 ↗](https://raw.githubusercontent.com/REIJI007/AdBlock_Rule_For_Clash/main/adblock_reject.txt) |

**配置**
---

```yaml
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
```

## 规则语义与生成产物

上游白名单只参与内部语义计算，不会输出到订阅。YAML/TXT classical 产物仅包含 `DOMAIN` 与 `DOMAIN-SUFFIX`；MRS 使用独立的 Mihomo `domain` behavior 输入转换。

优先级从高到低为：P0 important allow、P1 important block、P2 普通 allow、P3 普通 exact block、P4 普通 suffix block。**匹配范围与优先级独立建模**；`$badfilter` 按来源订阅及规范化后的完整规则身份撤销，而不是按域名粗略删除。

`DOMAIN` / `DOMAIN-SUFFIX` 无法表达“父域名整体拦截，但允许其中一个子域名”的集合差。严格编译会检查这类部分重叠，并在写入生成产物前失败；不会静默将 suffix 降级为 exact，也不会把有损结果伪装成无损结果。URL 路径、请求类型、第三方上下文、Cosmetic 规则和未解析的动态预处理条件不属于 DNS 域名规则的表达范围。

## 上游来源与构建可靠性

`sources.json` 为每个上游源保留稳定 ID，并显式配置：

- `defaultAction`：BLOCK 或 ALLOW。
- `plainDomainMatchType` / `hostsMatchType`：裸域名及 hosts 记录按 EXACT 或 SUFFIX 解释。
- `preprocessor`：NONE 或 UBO；UBO 来源会递归展开静态 `!#include`。
- `required` / `enabled`、可选 `sha256`、`maxBytes`、`retries` 与 `timeoutSeconds`。

下载器使用 HTTP 状态验证、`ResponseHeadersRead` 流式读取、读取过程字节上限、超时取消、重试、严格 UTF-8 解码和 SHA-256 指纹。必需来源下载失败时不发布新规则。构建会生成 `adblock_sources_manifest_yaml.json` / `adblock_sources_manifest_txt.json` 与 `adblock_build_report_yaml.json` / `adblock_build_report_txt.json`，用于追踪来源内容、失败项、预处理问题及不可表达冲突。

**注意：来源匹配元数据是从旧生成器行为和来源类型迁移得到的显式配置，并不等同于对全部上游源逐个完成规范审计。** 35 个启用的 ALLOW 来源的域名匹配范围、33 个启用的 UBO 来源，以及来源是否应为 required，仍值得人工抽样/复核。当前共有 317 条记录，其中 316 条启用、315 条启用且 required；`antiadblock_chinese.txt` 因上游 Git blob 为空而设为 enabled/optional。AdGuard SDNS 的 `Filters/exclusions.txt` 被上游配置用作组成过滤源的内部 exclusion input，而非独立 allowlist；该记录保留但设为 disabled/required=false，避免错误生成全局 ALLOW。来源内容及其规则语义也会随上游更新变化。

## 订阅格式

- YAML：Clash/Mihomo classical provider，`behavior: classical`、`format: yaml`。
- TXT：Clash/Mihomo classical provider，`behavior: classical`、`format: text`。
- MRS：由独立的 MRS 工作流从上游源重新编译规则，生成仅供本次转换使用的临时 domain-behavior YAML，再由 Mihomo 转换为二进制规则集。该临时输入不会作为 YAML 订阅产物发布，也不依赖 YAML 工作流的执行结果。

**YAML、TXT 与 MRS 是三条彼此独立的生成链路**：YAML workflow 只运行 YAML 入口并更新 `adblock_reject.yaml`；TXT workflow 只运行 TXT 入口并更新 `adblock_reject.txt`；MRS workflow 只运行 MRS 入口，独立下载和编译上游源，生成临时转换输入，再由 Mihomo 输出 `adblock_reject.mrs`。MRS 不监听、不等待 YAML/TXT workflow，也不读取它们生成的文件。三条链路可复用同一规则引擎，但触发、执行、诊断文件和提交目标各自独立。三个 workflow 使用各自独立的并发组，不会因其他格式的生成任务而排队等待；发布时各自通过 Git fetch/rebase 重试处理 `main` 分支上的并发更新。
