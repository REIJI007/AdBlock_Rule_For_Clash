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

<style>
  .subscription-table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    overflow: hidden;
    border: 1px solid #e5e7eb;
    border-radius: 12px;
    font-size: 14px;
    text-align: left;
    background: #ffffff;
  }

  .subscription-table thead {
    background: #f8fafc;
  }

  .subscription-table th {
    padding: 14px 20px;
    color: #475569;
    font-weight: 600;
    border-bottom: 1px solid #e5e7eb;
  }

  .subscription-table td {
    padding: 16px 20px;
    border-bottom: 1px solid #f1f5f9;
    color: #334155;
  }

  .subscription-table tbody tr:last-child td {
    border-bottom: none;
  }

  .subscription-table tbody tr {
    transition: background 0.2s ease;
  }

  .subscription-table tbody tr:hover {
    background: #f8fafc;
  }

  .subscription-table .format {
    display: inline-block;
    padding: 4px 9px;
    border-radius: 6px;
    background: #f1f5f9;
    color: #334155;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.4px;
  }

  .subscription-table .subscribe-link {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: #2563eb;
    font-weight: 500;
    text-decoration: none;
    transition: color 0.2s ease;
  }

  .subscription-table .subscribe-link:hover {
    color: #1d4ed8;
    text-decoration: underline;
    text-underline-offset: 3px;
  }

  @media (max-width: 480px) {
    .subscription-table th,
    .subscription-table td {
      padding: 13px 12px;
    }
  }
</style>

<table class="subscription-table">
  <thead>
    <tr>
      <th>格式</th>
      <th>GitHub 原始订阅</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><span class="format">YAML</span></td>
      <td>
        <a
          class="subscribe-link"
          href="https://raw.githubusercontent.com/REIJI007/AdBlock_Rule_For_Clash/main/adblock_reject.yaml"
          target="_blank"
          rel="noopener noreferrer"
        >
          获取订阅 ↗
        </a>
      </td>
    </tr>
    <tr>
      <td><span class="format">MRS</span></td>
      <td>
        <a
          class="subscribe-link"
          href="https://raw.githubusercontent.com/REIJI007/AdBlock_Rule_For_Clash/main/adblock_reject.mrs"
          target="_blank"
          rel="noopener noreferrer"
        >
          获取订阅 ↗
        </a>
      </td>
    </tr>
    <tr>
      <td><span class="format">TXT</span></td>
      <td>
        <a
          class="subscribe-link"
          href="https://raw.githubusercontent.com/REIJI007/AdBlock_Rule_For_Clash/main/adblock_reject.txt"
          target="_blank"
          rel="noopener noreferrer"
        >
          获取订阅 ↗
        </a>
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
