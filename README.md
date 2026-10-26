<div align="center">

# AdBlock Rule For Clash

**适用于 Clash 的广告域名拦截规则集**

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)]
[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)]
[![Last Commit](https://img.shields.io/badge/last%20commit-today-brightgreen)]
[![Stars](https://img.shields.io/github/stars/REIJI007/AdBlock_Rule_For_Clash)]
[![Issues](https://img.shields.io/github/issues/REIJI007/AdBlock_Rule_For_Clash)]

</div>

## 📥 订阅链接

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
