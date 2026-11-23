# 域名语义回归测试

## 执行方式

在仓库根目录运行：

```powershell
# Clash 仓库
pwsh -NoProfile -File ./tests/Invoke-SemanticRegression.ps1 -TargetFormat clash

# sing-box 仓库
pwsh -NoProfile -File ./tests/Invoke-SemanticRegression.ps1 -TargetFormat sing-box
```

测试不执行生产脚本的网络下载流程。它从被测生成器的 PowerShell AST 中载入真实解析函数，准备固定输入样本，然后执行生产脚本中的真实方案 A 投影区段和真实产物输出区段。这样测试不会另写一套并行解析器，也不会覆盖正式产物。

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

对固定探针域名集计算混淆矩阵：

- **语义一致率** = (TP + TN) / 全部探针
- **Precision** = TP / (TP + FP)，衡量产物规则的误拦截风险
- **Recall** = TP / (TP + FN)，衡量上游应拦截域名的覆盖率
- **F1** = Precision 与 Recall 的调和平均数

所有例外样本的预期阻断状态由人工标注，不使用被测程序自身的结果生成预期值。因方案 A 将父后缀降级为精确域名而导致的未列举子域漏拦截，会作为 FN 计入；不会把这类语义损失伪装成成功。

不适用于域名级输出的规则（例如仅限 script 的资源规则、路径规则、上下文规则、无法等价表达的通配符和非黑洞 DNS Rewrite）单独断言为 SKIP，不混入域名探针二分类分母。

测试报告写入 `tests/TestResults/semantic-metrics.json`，GitHub Actions 同时显示摘要并上传 JSON 工件。

## 重要边界

当前样本集是**可重复的语义回归基准**，不是数百个实时上游过滤源的全量命中率。要得到真实上游比例，还需下一阶段固定下载上游源快照、保留源文件与抓取时间，并建立更大规模且经人工审查的域名探针集合。单凭生成器产出的黑名单集合无法恢复所有规则的上下文和例外语义，因此不能把规则条数或域名去重数量当成语义遵循比例。
