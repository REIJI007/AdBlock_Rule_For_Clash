# 域名语义回归测试

## 执行方式

在仓库根目录运行：

```powershell
# Clash 仓库
pwsh -NoProfile -File ./tests/Invoke-SemanticRegression.ps1 -TargetFormat clash

# sing-box 仓库
pwsh -NoProfile -File ./tests/Invoke-SemanticRegression.ps1 -TargetFormat sing-box
```

固定样本回归测试不执行生产脚本的网络下载流程。它从被测生成器的 PowerShell AST 中载入真实解析函数，准备固定输入样本，然后执行生产脚本中的真实方案 A 投影区段和真实产物输出区段。另一个全量审计会执行完整生产生成器以抓取全部上游源并取得有效规则状态，再直接解析和核对仓库检出版本中的正式产物文件；生成器自身的输出重定向到临时目录，不会覆盖正式产物。

## 测试覆盖

- EXACT / SUFFIX 规则及其继承边界
- 精确白名单、后缀白名单与父子域冲突
- important 白名单 / 黑名单优先级回归
- badfilter 按完整规则身份撤销，而非按域名撤销
- NXDOMAIN、黑洞 IP、真实 IP 和 CNAME DNS 重写
- Hosts 一行多个主机名
- dnsmasq address / server / local
- 路径、通配符、资源类型及 domain context 约束规则的保守跳过
- 实际生成的 Clash YAML 或 sing-box JSON 结构与域名匹配行为

## 指标口径

本项目将两种不同问题分开报告，避免把固定探针准确度误当作产物条目遵循上游语义的比例。

### 全量上游语义一致率（本次需求指标）

- **语义一致率** = 产物中遵循上游规则语义的条数 / 产物域名条目总数 × 100%
- 每条唯一的 `DOMAIN` / `DOMAIN-SUFFIX` 产物规则计为一个条目。
- `DOMAIN` 只有在完整上游规则经优先级与白名单处理后，对应的有效规则类型仍为精确匹配时才计入分子；若上游后缀规则因子域例外被收窄为精确域名，则不计入分子。
- `DOMAIN-SUFFIX` 只有在上游存在对应后缀规则、该规则有效，且其覆盖范围内没有有效白名单例外时才计入分子。
- 不可证明与上游匹配范围一致的条目计入分母但不计入分子；分母为实际产物中的唯一规则条目，不是上游源规则数或探针数。
- 审计直接使用生成器内的完整 `urlList`（当前为 317 个 URL），执行生产解析、优先级、白名单冲突与投影代码；所有上游源必须成功下载，否则报告状态为 `incomplete` 且不计算百分比。
- 审计逐个计算上游源内容的 SHA-256，并将 URL 与内容哈希组合为聚合快照 SHA-256，报告保存聚合哈希以区分不同时间的上游数据快照。

执行：

```powershell
pwsh -NoProfile -File ./tests/Invoke-UpstreamSemanticAudit.ps1 -TargetFormat clash
```

机器可读报告为 `tests/TestResults/upstream-semantic-metrics.json`，由 GitHub Actions 上传。

### 固定探针回归指标

对固定探针域名集计算混淆矩阵：

- **语义一致率** = (TP + TN) / 全部探针
- **Precision** = TP / (TP + FP)，衡量产物规则的误拦截风险
- **Recall** = TP / (TP + FN)，衡量上游应拦截域名的覆盖率
- **F1** = Precision 与 Recall 的调和平均数

所有例外样本的预期阻断状态由人工标注，不使用被测程序自身的结果生成预期值。因方案 A 将父后缀降级为精确域名而导致的未列举子域漏拦截，会作为 FN 计入；不会把这类语义损失伪装成成功。

不适用于域名级输出的规则（例如仅限 script 的资源规则、路径规则、上下文规则、无法等价表达的通配符和非黑洞 DNS Rewrite）单独断言为 SKIP，不混入域名探针二分类分母。

测试报告写入 `tests/TestResults/semantic-metrics.json`，GitHub Actions 同时显示摘要并上传 JSON 工件。

## 重要边界

固定样本探针仍只是有限回归基准，不代表互联网域名总体上的误拦截率或漏拦截率。全量上游语义一致率衡量的是**产物条目本身是否保留上游规则的匹配范围**，不等同于对所有潜在域名执行混淆矩阵所得的 Recall / Precision。两类指标回答不同问题，应分别解读。
