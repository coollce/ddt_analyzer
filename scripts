#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDT 依赖漏洞分析器
用于分析第三方组件漏洞，结合规则引擎和 AI 评估给出升级建议

使用方式:
  # 阶段1：分析，输出待分析的 JSON
  python3 ddt_analyzer.py analyze <csv_file>

  # 阶段2：保存报告
  python3 ddt_analyzer.py report --results '<ai_results_json>' --output <output_dir>
"""

import argparse
import csv
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple, Optional

# ==================== 配置区域 ====================

# 低影响 CWE 集合（偏理论/DoS 类型）
LOW_IMPACT_CWE = {195, 681}

# ==================== 版本比较工具 ====================

def get_upgrade_gap(current: str, latest: str) -> str:
    """计算当前版本与最新版本之间的升级跨度"""
    try:
        cur = current.split(".")
        lat = latest.split(".")
        if int(lat[0]) > int(cur[0]):
            return "major"
        if len(lat) > 1 and len(cur) > 1 and int(lat[1]) > int(cur[1]):
            return "minor"
        if len(lat) > 2 and len(cur) > 2 and int(lat[2]) > int(cur[2]):
            return "patch"
    except Exception:
        pass
    return "unknown"


def major_version_gap(current: str, latest: str) -> bool:
    """判断是否跨主版本升级"""
    try:
        cur_major = int(current.split(".")[0])
        lat_major = int(latest.split(".")[0])
        return lat_major - cur_major >= 1
    except Exception:
        return False


# ==================== CSV 解析 ====================

def parse_cwe_ids(cwe_str: str) -> List[int]:
    """解析 CWE ID，支持多种格式: '917,871' 或 '[917, 871]' 或 '917'"""
    cwe_ids = []
    cwe_str = cwe_str.strip()
    if not cwe_str:
        return cwe_ids

    # 移除方括号
    cwe_str = cwe_str.strip("[]")

    # 分割并解析
    for part in cwe_str.split(","):
        part = part.strip()
        if part:
            try:
                cwe_ids.append(int(part))
            except ValueError:
                pass
    return cwe_ids


def parse_csv_row(row: Dict) -> Dict:
    """
    解析 CSV 行数据，转换为内部数据结构
    CSV 字段 -> 内部字段映射
    """
    # 解析 cweId（支持多种格式）
    cwe_ids = parse_cwe_ids(row.get("cweId", ""))

    return {
        # 组件信息
        "component_name": row.get("name", "").strip(),
        "component_group": row.get("group", "").strip(),
        "component_version": row.get("version", "").strip(),
        "latest_version": row.get("latestVersion", "").strip(),
        "purl": row.get("purl", "").strip(),

        # 漏洞信息
        "cve": row.get("vulnId", "").strip(),
        "severity": row.get("severity", "").strip(),
        "cvss": float(row.get("cvssV3BaseScore") or 0),
        "epss": float(row.get("epss") or 0),
        "epss_percentile": float(row.get("epss_percentile") or 0),
        "cwe_ids": cwe_ids,
        "description": row.get("description", "").strip(),
        "referer": row.get("referer", "").strip(),

        # 分析状态
        "suppressed": False  # CSV 输入默认未抑制
    }


def parse_csv_data(csv_content: str) -> List[Dict]:
    """
    解析 CSV 内容，返回规范化后的数据列表
    支持标准逗号分隔的 CSV 格式
    """
    lines = csv_content.strip().split("\n")
    if not lines:
        return []

    reader = csv.DictReader(lines)
    results = []
    for row in reader:
        # 跳过空行
        if not any(row.values()):
            continue
        parsed = parse_csv_row(row)
        results.append(parsed)

    return results


def parse_csv_file(file_path: str) -> List[Dict]:
    """从文件读取 CSV 并解析"""
    with open(file_path, "r", encoding="utf-8-sig") as f:
        content = f.read()
    return parse_csv_data(content)


# ==================== 规则预筛选 ====================

def rule_pre_filter(v: Dict) -> Tuple[str, str]:
    """
    规则预筛选引擎
    返回: (决策, 理由)
    决策类型: DROP / DEFER / CANDIDATE
    """
    # 1. 已抑制
    if v.get("suppressed", False):
        return "DROP", "漏洞已被抑制"

    # 2. CVSS 明确低
    if v["cvss"] < 7.0:
        return "DROP", "CVSS < 7.0"

    # 3. EPSS 显示现实利用概率极低
    if v["epss"] < 0.01 and v["epss_percentile"] < 0.7:
        return "DROP", "EPSS 显示现实利用概率极低"

    # 4. 漏洞类型偏理论 / DoS
    if any(cwe in LOW_IMPACT_CWE for cwe in v["cwe_ids"]):
        return "DEFER", "漏洞类型偏理论/DoS"

    # 5. 升级跨度过大（成本高）
    if v["latest_version"] and major_version_gap(v["component_version"], v["latest_version"]):
        return "DEFER", "升级跨度较大（跨主版本）"

    return "CANDIDATE", "进入 AI 风险分析"


# ==================== AI 输入构造 ====================

def build_ai_input(v: Dict) -> Dict:
    """
    构造 AI 分析所需的结构化输入数据
    """
    return {
        "component": {
            "name": v["component_name"],
            "version": v["component_version"],
            "latest_version": v["latest_version"],
            "purl": v["purl"]
        },
        "vulnerability": {
            "cve": v["cve"],
            "severity": v["severity"],
            "cvss": v["cvss"],
            "epss": v["epss"],
            "epss_percentile": v["epss_percentile"],
            "cwe_ids": v["cwe_ids"],
            "description": v["description"]
        },
        "context": {
            "upgrade_gap": get_upgrade_gap(v["component_version"], v["latest_version"]),
            "rule_decision": v["rule_decision"],
            "rule_reason": v["rule_reason"]
        }
    }


# ==================== Prompt 模板 ====================

SYSTEM_PROMPT = """你是一个企业级应用安全专家，负责评估第三方组件漏洞是否需要在现实生产环境中优先升级。
你必须基于输入数据做判断，不允许臆测不存在的事实。
你的目标是评估：在企业真实运行环境中，这个漏洞是否值得现在投入升级成本去处理。
你必须严格按 JSON Schema 输出结果，不允许输出任何多余内容。"""

USER_TEMPLATE = """请基于以下 JSON 数据评估该组件漏洞的现实风险与升级优先级。
评估时请综合考虑：
- CVSS 和 EPSS 反映的现实利用概率
- 漏洞描述是否表明需要特殊输入、恶意数据或特定使用方式
- 组件在企业环境中的常见用途
- 升级跨度（major/minor）对升级成本的影响
- 规则引擎给出的初步判断（context）
输入数据：
{data}
请按以下 JSON Schema 输出（只输出 JSON）, 不要输出 ```json ``` 这些干扰字符：
{{
  "exploit_difficulty": 0-5,
  "impact_severity": 0-5,
  "prerequisite_complexity": 0-5,
  "exploit_maturity": 0-5,
  "real_world_relevance": 0-5,
  "overall_risk_score": 0-25,
  "upgrade_priority": "LOW | MEDIUM | HIGH",
  "upgrade_recommendation": "YES | DEFER | NO",
  "reasoning": "尽可能表达出升级与不升级的明确理由"
}}"""


def build_prompt(ai_input: Dict) -> str:
    """构建完整的 User Prompt"""
    return USER_TEMPLATE.format(data=json.dumps(ai_input, ensure_ascii=False, indent=2))


# ==================== 决策引擎 ====================

def final_decision(v: Dict) -> str:
    """
    综合规则和 AI 分析结果，生成最终决策
    """
    ai = v.get("ai_assessment", {})
    score = ai.get("overall_risk_score", 0)

    # 根据升级跨度调整评分
    context = v.get("context", {})
    if context.get("upgrade_gap") == "major":
        score -= 3
    if context.get("rule_decision") == "DEFER":
        score -= 2

    # 最终决策
    if score >= 18:
        return "必须升级"
    elif score >= 13:
        return "建议升级"
    else:
        return "接受风险"


# ==================== 报告生成 ====================

def generate_report_rows(ai_results: List[Dict]) -> List[Dict]:
    """
    生成报告行数据
    ai_results: 包含 ai_assessment 字段的分析结果列表
    """
    rows = []
    for v in ai_results:
        ai = v.get("ai_assessment", {})
        decision = final_decision(v)

        # 截断过长的理由
        reasoning = ai.get("reasoning", "")
        if len(reasoning) > 200:
            reasoning = reasoning[:200] + "..."

        rows.append({
            "组件": v["component"]["name"],
            "版本": v["component"]["version"],
            "最新版本": v["component"]["latest_version"],
            "CVE": v["vulnerability"]["cve"],
            "CVSS": v["vulnerability"]["cvss"],
            "EPSS": v["vulnerability"]["epss"],
            "EPSS百分位": v["vulnerability"]["epss_percentile"],
            "CWE": ",".join(map(str, v["vulnerability"]["cwe_ids"])),
            "AI评分": ai.get("overall_risk_score"),
            "优先级": ai.get("upgrade_priority"),
            "决策": decision,
            "理由": reasoning
        })

    return rows


def format_markdown_table(rows: List[Dict]) -> str:
    """
    将报告数据格式化为 Markdown 表格
    """
    if not rows:
        return "无分析结果"

    headers = ["组件", "版本", "最新版本", "CVE", "CVSS", "EPSS", "AI评分", "优先级", "决策"]

    # 表头
    lines = ["| " + " | ".join(headers) + " |"]
    # 分隔线
    lines.append("|" + "|".join(["---"] * len(headers)) + "|")
    # 数据行
    for row in rows:
        values = [str(row.get(h, "")) for h in headers]
        lines.append("| " + " | ".join(values) + " |")

    return "\n".join(lines)


def generate_markdown_report(ai_results: List[Dict], stats: Dict, output_dir: Path) -> str:
    """
    生成完整的 Markdown 报告
    """
    rows = generate_report_rows(ai_results)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = f"""# DDT 漏洞分析报告

**分析时间：** {timestamp}
**总漏洞数：** {stats.get('total', 0)} 条

---

## 筛选统计

| 分类 | 数量 | 说明 |
|------|------|------|
| DROP | {stats.get('dropped', 0)} | CVSS < 7.0 或 EPSS 极低，跳过分析 |
| DEFER | {stats.get('deferred', 0)} | 升级跨度大或漏洞类型偏理论 |
| CANDIDATE | {stats.get('candidates', 0)} | 进入 AI 风险分析 |

---

## AI 分析结果

{format_markdown_table(rows)}

---

## 决策说明

- **必须升级** (score ≥ 18)：高风险漏洞，建议立即处理
- **建议升级** (score ≥ 13)：中等风险，建议近期安排升级
- **接受风险** (score < 13)：低风险，可暂时接受风险

---

## 详细理由

"""
    # 添加详细理由
    for v in ai_results:
        ai = v.get("ai_assessment", {})
        decision = final_decision(v)
        cve = v["vulnerability"]["cve"]
        name = v["component"]["name"]
        reasoning = ai.get("reasoning", "无")

        report += f"""### {name} - {cve} 【{decision}】

{reasoning}

---

"""

    return report


def save_csv_report(rows: List[Dict], output_path: Path) -> Path:
    """保存 CSV 报告"""
    if not rows:
        with open(output_path, "w", encoding="utf-8-sig") as f:
            f.write("")
        return output_path

    fieldnames = list(rows[0].keys())
    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return output_path


def save_markdown_report(content: str, output_path: Path) -> Path:
    """保存 Markdown 报告"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    return output_path


# ==================== 分析阶段 ====================

def cmd_analyze(csv_path: str) -> Dict:
    """
    分析阶段：解析 CSV，规则筛选，输出 ai_inputs
    """
    # 解析 CSV
    csv_data = parse_csv_file(csv_path)
    if not csv_data:
        return {
            "success": False,
            "error": "CSV 文件为空或无法解析",
            "ai_inputs": [],
            "stats": {"total": 0, "dropped": 0, "deferred": 0, "candidates": 0}
        }

    ai_inputs = []
    dropped = []
    deferred = []

    for v in csv_data:
        # 规则预筛选
        decision, reason = rule_pre_filter(v)
        v["rule_decision"] = decision
        v["rule_reason"] = reason

        if decision == "DROP":
            dropped.append(v)
        elif decision == "DEFER":
            deferred.append(v)
            # DEFER 也进入 AI 分析
            ai_inputs.append(build_ai_input(v))
        else:  # CANDIDATE
            ai_inputs.append(build_ai_input(v))

    stats = {
        "total": len(csv_data),
        "dropped": len(dropped),
        "deferred": len(deferred),
        "candidates": len(ai_inputs)
    }

    return {
        "success": True,
        "ai_inputs": ai_inputs,
        "stats": stats,
        "prompts": {
            "system": SYSTEM_PROMPT,
            "user_template": USER_TEMPLATE
        }
    }


# ==================== 报告阶段 ====================

def cmd_report(results_json: str, output_dir: str) -> Dict:
    """
    报告阶段：接收 AI 分析结果，生成报告文件
    """
    # 解析 AI 结果
    try:
        ai_results = json.loads(results_json)
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"JSON 解析失败: {e}"
        }

    if not ai_results:
        return {
            "success": False,
            "error": "AI 分析结果为空"
        }

    # 设置输出目录
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # 生成报告
    stats = {"total": len(ai_results), "candidates": len(ai_results)}
    markdown_content = generate_markdown_report(ai_results, stats, output_path)
    rows = generate_report_rows(ai_results)

    # 保存文件
    csv_path = output_path / "vulnerability_report.csv"
    md_path = output_path / "analysis_report.md"

    save_csv_report(rows, csv_path)
    save_markdown_report(markdown_content, md_path)

    return {
        "success": True,
        "output_dir": str(output_path),
        "files": {
            "csv": str(csv_path),
            "markdown": str(md_path)
        },
        "stats": stats,
        "summary": format_markdown_table(rows)
    }


# ==================== 主入口 ====================

def main():
    parser = argparse.ArgumentParser(
        description="DDT 依赖漏洞分析器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 阶段1：分析
  python3 ddt_analyzer.py analyze test.csv

  # 阶段2：保存报告
  python3 ddt_analyzer.py report --results '[...]' --output ./report/
"""
    )

    subparsers = parser.add_subparsers(dest="command", help="子命令")

    # analyze 子命令
    analyze_parser = subparsers.add_parser("analyze", help="分析阶段：解析CSV并筛选")
    analyze_parser.add_argument("csv_file", help="CSV 文件路径")

    # report 子命令
    report_parser = subparsers.add_parser("report", help="报告阶段：生成报告文件")
    report_parser.add_argument("--results", "-r", required=True, help="AI 分析结果 (JSON 字符串)")
    report_parser.add_argument("--output", "-o", default=None, help="输出目录 (默认: 当前目录/时间戳)")

    args = parser.parse_args()

    if args.command == "analyze":
        result = cmd_analyze(args.csv_file)
        # 输出 JSON 供 Agent 使用
        print(json.dumps(result, ensure_ascii=False, indent=2))

    elif args.command == "report":
        # 默认输出目录
        output_dir = args.output
        if not output_dir:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = f"vulnerability_report_{timestamp}"

        result = cmd_report(args.results, output_dir)
        print(json.dumps(result, ensure_ascii=False, indent=2))

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
