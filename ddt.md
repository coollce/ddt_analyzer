# DDT 依赖漏洞分析

## 功能说明

当用户请求分析第三方依赖漏洞时，使用此技能进行智能分析，结合规则引擎和 AI 评估给出升级建议。

## 触发条件

用户请求分析漏洞数据，例如：
- "使用 DDT 分析漏洞"
- "帮我分析这个 CSV 中的漏洞"
- "分析这些漏洞数据"

## 执行流程

### 步骤 1：获取 CSV 数据

确认用户提供的数据格式，CSV 应包含以下字段：
- name, group, version, latestVersion, purl
- vulnId, severity, cvssV3BaseScore
- epss, epss_percentile, cweId
- description, referer

### 步骤 2：执行分析阶段

运行脚本获取筛选后的数据：

```bash
python3 ~/.cursor/rules/scripts/ddt_analyzer.py analyze <csv_file>
```

脚本输出 JSON：
- `ai_inputs`: 需要进入 AI 分析的数据数组
- `stats`: 筛选统计（total/dropped/deferred/candidates）
- `prompts`: System Prompt 和 User Template

向用户展示筛选统计。

### 步骤 3：AI 风险评估

对每条 `ai_inputs` 数据，使用 Agent LLM 进行分析。

**System Prompt:**
```
你是一个企业级应用安全专家，负责评估第三方组件漏洞是否需要在现实生产环境中优先升级。
你必须基于输入数据做判断，不允许臆测不存在的事实。
你的目标是评估：在企业真实运行环境中，这个漏洞是否值得现在投入升级成本去处理。
你必须严格按 JSON Schema 输出结果，不允许输出任何多余内容。
```

**User Prompt 格式:**
```
请基于以下 JSON 数据评估该组件漏洞的现实风险与升级优先级。
评估时请综合考虑：
- CVSS 和 EPSS 反映的现实利用概率
- 漏洞描述是否表明需要特殊输入、恶意数据或特定使用方式
- 组件在企业环境中的常见用途
- 升级跨度（major/minor）对升级成本的影响
- 规则引擎给出的初步判断（context）

输入数据：
{ai_input_json}

请按以下 JSON Schema 输出（只输出 JSON）：
{
  "exploit_difficulty": 0-5,
  "impact_severity": 0-5,
  "prerequisite_complexity": 0-5,
  "exploit_maturity": 0-5,
  "real_world_relevance": 0-5,
  "overall_risk_score": 0-25,
  "upgrade_priority": "LOW | MEDIUM | HIGH",
  "upgrade_recommendation": "YES | DEFER | NO",
  "reasoning": "尽可能表达出升级与不升级的明确理由"
}
```

### 步骤 4：保存报告

将 AI 分析结果传给脚本生成报告：

```bash
python3 ~/.cursor/rules/scripts/ddt_analyzer.py report \
  --results '<ai_results_json>' \
  --output <output_dir>
```

### 步骤 5：展示结果

1. 展示 Markdown 表格（脚本输出的 summary）
2. 告知报告保存位置
3. 提供后续交互：可追问漏洞详情

## 决策规则

- **必须升级**: 综合评分 >= 18
- **建议升级**: 综合评分 >= 13
- **接受风险**: 综合评分 < 13

综合评分调整：
- upgrade_gap == "major": 评分 -3
- rule_decision == "DEFER": 评分 -2

## 筛选规则

**DROP（跳过分析）:**
- CVSS < 7.0
- EPSS < 0.01 且 epss_percentile < 0.7

**DEFER（暂缓）:**
- CWE 在 {195, 681} 中（偏理论/DoS）
- 升级跨度大（跨主版本）

**CANDIDATE（进入 AI 分析）:**
- 未满足上述条件

## 脚本位置

分析脚本位于：`~/.cursor/rules/scripts/ddt_analyzer.py`

如需全局使用，可将脚本复制到任意目录并在执行时指定路径。