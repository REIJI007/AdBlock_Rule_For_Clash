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
    url: https://raw.githubusercontent.com/REIJI007/AdBlock_Rule_For_Clash/main/adblock_reject.yaml
    path: ./ruleset/adblock_reject.yaml
    interval: 120
    timeout: 30

rules:
  - GEOSITE,category-ads-all,REJECT
  - RULE-SET,adblock,REJECT
```


## 构建架构与九项升级

### 代码与配置分层

- `AdBlockRuleEngine.psm1`：唯一的规则处理核心，负责下载、预处理、解析、语义裁决、冲突检测、压缩和序列化。
- `adblock_rule_generator_yaml.ps1`：YAML 专用入口，只生成 `adblock_reject.yaml`。
- `adblock_rule_generator_txt.ps1`：TXT 专用入口，只生成 `adblock_reject.txt`。
- `adblock_rule_generator_mrs.ps1`：MRS 专用入口，独立生成临时 domain-behavior YAML 输入，再由 Mihomo 转换为 `adblock_reject.mrs`。
- `config/upstream-sources.json`：集中保存 317 个上游源及稳定 ID、动作语义、语法类型、预处理方式、匹配范围、必需性和下载限制。

### 九项升级

1. **统一处理核心**：从原本两份 1,100 行、仅输出路径不同的脚本中抽离共享模块，保留三个固定格式入口。
2. **上游源配置化**：将 317 个唯一 URL 移入独立 JSON 配置，校验稳定 ID、HTTPS、唯一性、动作、语法和下载参数。
3. **五级优先级**：P0 important allow、P1 important block、P2 普通 allow、P3 精确 block、P4 后缀 block；优先级与匹配范围分开建模。
4. **精确 badfilter**：按来源订阅与规范化规则身份撤销，不按域名粗略删除。
5. **PSL / DNS 语义**：识别 PSL exact、wildcard、exception，统一 IDN、DNS label 和后缀边界处理。
6. **反向域名 Trie**：使用反向标签索引执行 suffix 匹配、冲突查询和父级覆盖剪枝。
7. **无损性检查**：allowlist 只用于内部求值；无法用正向 DOMAIN / DOMAIN-SUFFIX 表达的 allow-hole 在严格模式下阻止覆盖发布。
8. **语法边界与预处理**：展开 Hosts 多域名和标记源中的静态 uBO `!#include`；动态条件、未知语法和 URL/请求上下文/Cosmetic 规则不被猜测或扩大为全域名拦截。
9. **可靠构建与独立发布**：流式限长下载、HTTP/编码/空内容/HTML 校验、超时、重试、SHA-256 清单、原子写入、构建报告和回归测试；TXT、YAML、MRS 三条工作流各自触发、构建和发布。

### 工作流解耦约束

TXT、YAML、MRS 三条工作流各自拥有 push 路径、20 分钟 schedule、手动触发器和独立并发组。它们只提交自己的产物。MRS 在自己的任务中重新下载并编译来源，临时输入仅存在于该次运行环境；**MRS 不读取 YAML/TXT 产物，不由 YAML/TXT 工作流触发，也不等待它们完成**。并发组彼此独立，提交冲突通过 fetch/rebase/push 重试解决。

### 来源元数据审计边界

当前保留 317 个来源记录，其中 316 个启用、315 个启用且 required；35 个启用来源标记为 ALLOW，33 个来源标记为 uBO 静态 include 预处理。匹配范围和 ALLOW 分类是从旧生成器行为迁移的显式配置，尚未逐源进行外部规范审计；当前 `syntax` 默认为 `AUTO`，由解析器自动识别。AdGuard SDNS 的 `Filters/exclusions.txt` 作为父过滤器的内部排除输入处理，默认不作为全局 ALLOW 源启用。

严格构建的 Pester / 配置合同测试不等同于 316 个实时上游源的端到端构建；上游内容变化、临时源故障和无法无损表达的冲突仍需由实际构建报告确认。
