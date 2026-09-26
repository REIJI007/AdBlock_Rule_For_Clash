<div align="center">

# AdBlock Rule For Clash

**适用于 Clash 的广告域名拦截规则集**

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)]
[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)]
[![Last Commit](https://img.shields.io/badge/last%20commit-today-brightgreen)]
[![Stars](https://img.shields.io/github/stars/REIJI007/AdBlock_Rule_For_Clash)]
[![Issues](https://img.shields.io/github/issues/REIJI007/AdBlock_Rule_For_Clash)]

</div>

**链接**
---

<table>
  <thead>
    <tr>
      <th>格式</th>
      <th>订阅链接</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><b>YAML</b></td>
      <td>
        <a href="https://raw.githubusercontent.com/REIJI007/AdBlock_Rule_For_Clash/main/adblock_reject.yaml">GitHub原始链接</a> ·
        <a href="https://cdn.jsdelivr.net/gh/REIJI007/AdBlock_Rule_For_Clash@main/adblock_reject.yaml">jsDelivr加速链接</a> ·
        <a href="https://cdn.statically.io/gh/REIJI007/AdBlock_Rule_For_Clash/main/adblock_reject.yaml">Statically加速链接</a>
      </td>
    </tr>
    <tr>
      <td><b>MRS</b></td>
      <td>
        <a href="https://raw.githubusercontent.com/REIJI007/AdBlock_Rule_For_Clash/main/adblock_reject.mrs">GitHub原始链接</a> ·
        <a href="https://cdn.jsdelivr.net/gh/REIJI007/AdBlock_Rule_For_Clash@main/adblock_reject.mrs">jsDelivr加速链接</a> ·
        <a href="https://cdn.statically.io/gh/REIJI007/AdBlock_Rule_For_Clash/main/adblock_reject.mrs">Statically加速链接</a>
      </td>
    </tr>
    <tr>
      <td><b>TXT</b></td>
      <td>
        <a href="https://raw.githubusercontent.com/REIJI007/AdBlock_Rule_For_Clash/main/adblock_reject.txt">GitHub原始链接</a> ·
        <a href="https://cdn.jsdelivr.net/gh/REIJI007/AdBlock_Rule_For_Clash@main/adblock_reject.txt">jsDelivr加速链接</a> ·
        <a href="https://cdn.statically.io/gh/REIJI007/AdBlock_Rule_For_Clash/main/adblock_reject.txt">Statically加速链接</a>
      </td>
    </tr>
  </tbody>
</table>

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
