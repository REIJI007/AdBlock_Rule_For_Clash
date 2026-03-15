[![GPL 3.0 license](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL%203.0)
[![CC BY-NC-SA 4.0 license](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA%204.0)
<!-- 居中的大标题 -->
<h1 align="center" style="font-size: 70px; margin-bottom: 20px;">AdBlock_Rule_For_Clash</h1>

<!-- 居中的副标题 -->
<h2 align="center" style="font-size: 30px; margin-bottom: 40px;">适用于Clash（premium核心与mihomo核心）的广告域名拦截RULE-SET规则集，每20分钟更新一次</h2>

<!-- 徽章（根据需要调整） -->
<p align="center" style="margin-bottom: 40px;">
    <img src="https://img.shields.io/badge/last%20commit-today-brightgreen" alt="last commit" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/forks/REIJI007/AdBlock_Rule_For_Clash" alt="forks" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/stars/REIJI007/AdBlock_Rule_For_Clash" alt="stars" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/issues/REIJI007/AdBlock_Rule_For_Clash" alt="issues" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/license/REIJI007/AdBlock_Rule_For_Clash" alt="license" style="margin-right: 10px;">
</p>

**一、从多个广告过滤器中提取拦截域名条目，删除重复项，并将它们转换为兼容Clash的payload列表格式，一行仅一条规则。该列表可以用作Clash的rule-providers以阻止广告域名， powershell脚本每20分钟自动执行并将生成的文件发布在release中.三个文件的下载地址分别如下，其中adblock_reject.yaml和adblock_reject.txt是Matcher Ruleset格式数组构成的payload列表，adblock_reject.mrs则是由mihomo核心将adblock_reject.yaml编译转化得来的规则集**
<br>
<br>
<table border="1" style="border-collapse: collapse; width: 100%; font-family: Arial, sans-serif;">
  <tr>
    <td colspan="2" style="background-color: #f2f2f2; font-weight: bold; text-align: center; padding: 10px;">订阅地址</td>
  </tr>
  <tr>
    <td style="padding: 8px;">YAML</td>
    <td style="padding: 8px;">
      <strong><a href="https://raw.githubusercontent.com/REIJI007/AdBlock_Rule_For_Clash/main/adblock_reject.yaml" style="color: #0066cc;">Github原始链接</a></strong> | 
      <strong><a href="https://cdn.jsdelivr.net/gh/REIJI007/AdBlock_Rule_For_Clash@main/adblock_reject.yaml" style="color: #0066cc;">jsDelivr 加速链接</a></strong>
    </td>
  </tr>
  <tr>
    <td style="padding: 8px;">MRS</td>
    <td style="padding: 8px;">
      <strong><a href="https://raw.githubusercontent.com/REIJI007/AdBlock_Rule_For_Clash/main/adblock_reject.mrs" style="color: #0066cc;">Github原始链接</a></strong> | 
      <strong><a href="https://cdn.jsdelivr.net/gh/REIJI007/AdBlock_Rule_For_Clash@main/adblock_reject.mrs" style="color: #0066cc;">jsDelivr 加速链接</a></strong>
    </td>
  </tr>
  <tr>
    <td style="padding: 8px;">TXT</td>
    <td style="padding: 8px;">
      <strong><a href="https://raw.githubusercontent.com/REIJI007/AdBlock_Rule_For_Clash/main/adblock_reject.txt" style="color: #0066cc;">Github原始链接</a></strong> | 
      <strong><a href="https://cdn.jsdelivr.net/gh/REIJI007/AdBlock_Rule_For_Clash@main/adblock_reject.txt" style="color: #0066cc;">jsDelivr 加速链接</a></strong>
    </td>
  </tr>
</table>

<hr>

## 警告:本过滤器订阅有可能破坏某些网站的功能，也有可能封禁某些色情、赌博网站，使用前请斟酌考虑，如有误杀请积极向上游issue反馈，本仓库仅提供去重、筛选、合并功能

<hr>
<br>

**二、关于本仓库使用方式：**

  *使用方式：将下面对应格式的配置文件中rule-providers字段和rules字段内容添加到你的配置文件充当远程规则集，需要特别注意配置文件的缩进和对齐（同步本仓库的云端部署的远程规则集配置)*
<hr>


```conf
#YAML格式外部远程拦截域名规则集
dns:
  enable: true
  nameserver-policy:
    "rule-set:adblock": "rcode://refused"		#DNS模块拦截
    
    
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
  - RULE-SET,adblock,REJECT			#路由模块拦截
```

<hr>


**三、本仓库引用的广告过滤规则来源请查看```Referencing rule sources.txt```（目前106个来源）。至于是否误杀域名完全取决于这些处于上游的广告过滤器的域名拦截行为，你可按在本地使用powershell脚本进行DIY本地定制化，亦或者fork本仓库自行DIY**


**四、特别鸣谢**

1. [mihomo](https://github.com/MetaCubeX/mihomo)
2. [Adguard](https://github.com/AdguardTeam/AdGuardFilters)

## LICENSE
- [CC-BY-SA-4.0 License](https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA%204.0)
- [GPL-3.0 License](https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL%203.0)



