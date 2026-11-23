# 域名语义回归与全量上游评估

## 执行方式

在仓库根目录运行：

\`\`\`powershell
pwsh -NoProfile -File ./tests/Invoke-SemanticRegression.ps1 -TargetFormat clash
pwsh -NoProfile -File ./tests/Invoke-UpstreamSemanticAudit.ps1 -TargetFormat clash
\`\`\`

第一项是离线解析器与产物结构回归，不执行网络下载；第二项抓取生成器列出的全部上游源，并基于完整有效域名规则集合评估仓库中已提交的正式产物。审计不会覆盖正式产物，生成器临时输出和日志均重定向到临时目录。

## 主指标：完整上游域名规则边界评估

总体语义一致率、Precision、Recall、F1 以及 TP / FP / TN / FN 均由 \`Invoke-UpstreamSemanticAudit.ps1\` 计算。**不再使用 34 个固定探针估算总体性能。**

评估语料从所有成功抓取、经生产解析器解析、badfilter 撤销及优先级处理后的域名级规则构建，包含：

- 有效精确黑名单域名（EXACT）
- 有效后缀黑名单域名（SUFFIX）
- 有效精确白名单域名
- 有效后缀白名单域名
- 正式产物中的全部 DOMAIN / DOMAIN-SUFFIX 条目，以便识别产物独有的误拦截

为了表示精确匹配和后缀匹配的有限规则树，审计会把每个唯一规则域名及其所有父域作为语义边界。对每个边界评估两个代表点：边界域名本身，以及一个与任何已知规则域不冲突的代表性子域。所有显式规则域及其父域均纳入边界，因此每个代表子域覆盖相应的、未被更具体规则分割的后代区域。

对每个代表点：

- 上游预期行为由生产生成器的 \`Get-EffectiveStatus\` 计算，BLACKLIST 为应拦截，WHITELIST / UNKNOWN 为应放行。
- 实际行为由已提交产物的 DOMAIN 精确匹配与 DOMAIN-SUFFIX 后缀匹配计算。
- TP：上游要求拦截，产物也拦截。
- FN：上游要求拦截，产物未拦截。
- TN：上游要求放行，产物也放行。
- FP：上游要求放行，产物却拦截。

公式：

\`\`\`text
语义一致率 = (TP + TN) / (TP + FP + TN + FN) × 100%
Precision = TP / (TP + FP) × 100%
Recall = TP / (TP + FN) × 100%
F1 = 2 × Precision × Recall / (Precision + Recall)
\`\`\`

此方法覆盖完整上游规则集合中可由域名级精确 / 后缀规则表达的全部规则边界。它同时将产物漏掉的源规则计入 FN，并将产物额外覆盖的域名区域计入 FP。

### 统计边界

- 必须全部上游源成功下载且内容非空，才会输出百分比；任一源失败时报告标记为 \`incomplete\`，所有总体指标均为 null。
- 路径、资源类型、上下文、正则、通配符及非黑洞 DNS Rewrite 等不能等价表达为域名规则的上游行，不强行纳入域名二分类，而是不强行纳入域名二分类；跳过或撤销数量及按原因分类会独立写入报告。
- 代表点按规则边界等权，不按真实互联网流量、注册域名数量或域名空间体积加权。因此这些指标衡量的是完整有限规则边界上的语义一致性，不是现实用户的广告拦截命中率。
- 这是一种对 EXACT / SUFFIX 规则树的有限等价类评估：每个显式边界及其父域被检查，另用一个未占用的子域代表该边界下未被更具体规则分割的后代区域。
- 报告保存上游源 URL + SHA-256 聚合快照、产物 SHA-256、有效规则域名数、边界节点数、评估点数、混淆矩阵和最多 100 条 FP/FN 样本。

机器可读报告：\`tests/TestResults/upstream-semantic-metrics.json\`。

## 离线解析器回归

\`tests/fixtures/semantic-cases.json\` 和 \`Invoke-SemanticRegression.ps1\` 保留固定规则样本，用于验证：

- EXACT / SUFFIX 及其继承语义
- 精确白名单、后缀白名单与 important 优先级
- badfilter 按完整规则身份撤销
- NXDOMAIN、黑洞 IP、真实 IP 和 CNAME DNS Rewrite
- Hosts 多主机名解析
- dnsmasq address / server / local
- 路径、通配符、资源类型和上下文约束规则的保守跳过
- 输出规则必须来自生成器最终规则集合，YAML 结构合法

该离线测试只报告解析与结构断言，不生成 Accuracy / Precision / Recall / F1，也不把固定样本当作总体估计。机器可读报告：\`tests/TestResults/parser-regression.json\`。
