"""Redraw the user's architecture while preserving its module relationships."""

from pathlib import Path
import importlib.util
import json
import xml.etree.ElementTree as ET


OUT = Path(__file__).resolve().parent
REFERENCE = Path("C:/Users/h2696/Desktop/Architecture Diagram.drawio")
HELPER = OUT.parent / "architecture-ppt" / "generate_architecture.py"
spec = importlib.util.spec_from_file_location("architecture_layout_helpers", HELPER)
draw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(draw)
draw.OUT = OUT
box, label, card, edge = draw.box, draw.label, draw.card, draw.edge
NAVY, GOLD, MUTED, BG, LINE = draw.NAVY, draw.GOLD, draw.MUTED, draw.BG, draw.LINE


def build_layout():
    box("background", 0, 0, 1920, 1080, BG, "none", False)
    box("header", 0, 0, 1920, 120, NAVY, "none", False)
    box("header_rule", 0, 120, 1920, 6, GOLD, "none", False)
    label("title", "VulnHunter 分析与利用架构", 70, 26, 1400, 48, 30, "#FFFFFF", True)
    label("subtitle", "上下文输入 → 静态分析 → 攻击规划 → 动态验证 → PoC 与漏洞报告",
          70, 77, 1480, 30, 18, "#DCE4F1")
    label("header_tag", "ANALYSIS & EXPLOITATION", 1510, 48, 340, 35, 14, "#DCE4F1", align="right")

    box("inputs", 65, 165, 460, 605, "#FFFFFF")
    label("input_heading", "上下文输入与 LLM", 90, 182, 405, 38, 24, NAVY, True)
    card("prompt", "审计提示词", ["Prompt"], 95, 255, 220, 100, title_size=22)
    card("tree", "项目目录树", [], 350, 255, 145, 110, title_size=20)
    label("tree_en", "Directory Tree", 372, 308, 101, 28, 14, MUTED)
    card("codebase", "代码仓库", ["Codebase", "源代码与项目依赖"],
         95, 550, 220, 130, title_size=22)
    card("llm", "LLM", ["推理与决策"], 350, 465, 145, 115, title_size=28,
         fill="#EEF2F8", stroke="#A7B9D3")

    box("static_group", 560, 165, 950, 200, "#FFFFFF")
    label("static_group_heading", "静态分析工具集", 585, 179, 890, 38, 24, NAVY, True)
    card("joern", "Joern", ["CPG · CodeBadger 接入"], 595, 220, 260, 80, title_size=22)
    card("semgrep", "Semgrep", ["规则扫描"], 905, 220, 250, 80, title_size=22)
    card("codeql", "CodeQL", ["查询与数据流分析"], 1205, 220, 275, 80, title_size=22)
    box("static_tools", 595, 320, 885, 40, NAVY, "none")
    label("static_tools_title", "静态分析工具（Static Analysis Tools）",
          615, 321, 845, 38, 22, "#FFFFFF", True, "center")

    box("loop", 560, 390, 950, 380, "#EEF2F8", "#A7B9D3", line_width=1.8)
    label("loop_title", "分析与利用闭环", 860, 403, 600, 37, 24, NAVY, True)
    label("loop_en", "Analysis & Exploitation Loop", 860, 439, 600, 24, 14, MUTED)
    card("static_analysis", "静态分析", ["Static Analysis", "代码线索与风险路径"],
         595, 470, 260, 110, title_size=24)
    card("attack_planning", "攻击规划", ["Attack Planning", "构造可行的验证方案"],
         905, 470, 250, 110, title_size=24)
    card("dynamic", "动态验证", ["Dynamic Verification", "执行验证并观察安全影响"],
         1215, 470, 265, 110, title_size=24)
    box("state", 595, 625, 885, 115, "#FFF9EB", GOLD)
    label("state_title", "状态管理 State Management", 900, 633, 555, 32, 20, NAVY, True)
    label("state_facts", "事实与证据", 615, 681, 155, 45, 18, MUTED)
    box("blackboard", 850, 682, 410, 45, "#FFFFFF", GOLD)
    label("blackboard_title", "黑板 Blackboard", 865, 684, 380, 41, 22, NAVY, True, "center")

    box("output", 1590, 460, 265, 180, "#FFF9EB", GOLD)
    label("output_poc", "PoC 生成", 1612, 477, 221, 38, 24, NAVY, True)
    label("output_report", "漏洞报告", 1612, 514, 221, 38, 24, NAVY, True)
    label("output_en1", "PoC Generation &", 1612, 554, 221, 25, 16, MUTED)
    label("output_en2", "Vulnerability Report", 1612, 579, 221, 25, 16, MUTED)
    label("output_evidence", "复现步骤 · 执行证据", 1612, 607, 221, 27, 18, MUTED)

    card("docker", "Docker 容器", ["Docker Container", "代码挂载与受控执行"],
         365, 875, 250, 110, title_size=22, fill="#FFF9EB", stroke=GOLD)
    card("shell", "交互式 Shell", ["Interactive Shell"],
         700, 835, 250, 85, title_size=22, fill="#FFF9EB", stroke=GOLD)
    card("creation", "容器创建", ["Container Creation"],
         700, 950, 250, 80, title_size=22, fill="#FFF9EB", stroke=GOLD)
    box("subagent", 1175, 835, 330, 195, "#FFF9EB", GOLD)
    label("subagent_title", "子 Agent（Subagent）", 1200, 846, 280, 35, 22, NAVY, True)
    card("executor", "Executor", ["动态操作与执行证据", "容器工具 · 追加黑板"],
         1210, 890, 260, 110, title_size=24, stroke=GOLD)

    # Preserve the reference's 15 directed relationships, including the reverse
    # start arrow that denotes Subagent -> Dynamic Verification in its XML.
    edge("prompt_llm", "prompt", "llm", [(315, 305), (333, 305), (333, 490), (350, 490)])
    edge("tree_llm", "tree", "llm", [(417, 365), (417, 465)])
    label("tree_relation", "目录结构", 427, 410, 83, 27, 14, MUTED)
    edge("code_llm", "codebase", "llm", [(315, 615), (333, 615), (333, 545), (350, 545)])
    edge("llm_loop", "llm", "loop", [(495, 523), (560, 523)])
    edge("joern_tools", "joern", "static_tools", [(725, 300), (725, 320)])
    edge("semgrep_tools", "semgrep", "static_tools", [(1030, 300), (1030, 320)])
    edge("codeql_tools", "codeql", "static_tools", [(1343, 300), (1343, 320)])
    edge("tools_static", "static_tools", "static_analysis", [(725, 360), (725, 470)])
    label("mcp_label", "MCP Server", 747, 393, 107, 28, 14, MUTED)
    edge("loop_output", "loop", "output", [(1510, 525), (1590, 525)])
    edge("volume", "codebase", "docker", [(205, 680), (205, 930), (365, 930)], MUTED, True)
    label("volume_label", "Volume 挂载", 223, 780, 140, 30, 18, MUTED)
    edge("docker_shell", "docker", "shell", [(615, 905), (650, 905), (650, 878), (700, 878)])
    edge("docker_creation", "docker", "creation", [(615, 955), (650, 955), (650, 990), (700, 990)])
    edge("shell_executor", "shell", "subagent", [(950, 878), (1000, 878), (1000, 885), (1175, 885)])
    edge("creation_executor", "creation", "subagent", [(950, 990), (1000, 990), (1000, 980), (1175, 980)])
    label("docker_mcp_label", "docker-mcp", 1020, 920, 135, 28, 14, MUTED)
    edge("executor_dynamic", "subagent", "dynamic",
         [(1345, 835), (1345, 800), (1545, 800), (1545, 560), (1480, 560)])
    label("executor_dynamic_label", "支撑动态验证", 1562, 715, 145, 30, 14, MUTED)

    # Make the implicit order and evidence feedback in the original explicit.
    edge("analysis_plan", "static_analysis", "attack_planning", [(855, 525), (905, 525)])
    edge("plan_verify", "attack_planning", "dynamic", [(1155, 525), (1215, 525)])
    edge("verify_facts", "dynamic", "blackboard", [(1345, 580), (1345, 705), (1260, 705)], GOLD)
    label("verify_facts_label", "追加验证事实", 1361, 645, 108, 30, 14, "#80661E")
    edge("facts_analysis", "blackboard", "static_analysis", [(850, 705), (790, 705), (790, 580)], GOLD)
    label("feedback_label", "事实反馈", 694, 593, 90, 28, 14, "#80661E")

    box("legend_flow", 80, 1051, 48, 2, NAVY, "none", False)
    label("legend_flow_label", "模块调用 / 数据流", 143, 1037, 210, 30, 14, MUTED)
    box("legend_feedback", 390, 1051, 48, 2, GOLD, "none", False)
    label("legend_feedback_label", "状态与证据反馈", 453, 1037, 190, 30, 14, MUTED)
    for n, x in enumerate((685, 705, 725)):
        box(f"legend_mount_{n}", x, 1051, 12, 2, MUTED, "none", False)
    label("legend_mount_label", "Volume 挂载", 753, 1037, 190, 30, 14, MUTED)
    label("footer", "关系依据：用户提供的 Architecture Diagram.drawio",
          1135, 1037, 720, 30, 14, MUTED, align="right")


def validate_reference():
    original = ET.parse(REFERENCE)
    node_map = {
        "4": "llm", "24": "prompt", "26": "codebase", "29": "tree",
        "30": "joern", "32": "semgrep", "33": "codeql", "34": "static_tools",
        "42": "loop", "45": "static_analysis", "46": "attack_planning",
        "47": "dynamic", "48": "state", "49": "blackboard", "53": "docker",
        "56": "shell", "57": "creation", "59": "subagent", "58": "executor", "70": "output",
    }
    expected = set()
    for cell in original.findall(".//mxCell"):
        if cell.get("edge") != "1":
            continue
        start = node_map[cell.get("source").rsplit("-", 1)[1]]
        end = node_map[cell.get("target").rsplit("-", 1)[1]]
        style = dict(s.split("=", 1) for s in cell.get("style", "").split(";") if "=" in s)
        if style.get("endArrow") == "none" and style.get("startArrow", "none") != "none":
            start, end = end, start
        expected.add((start, end))
    actual = {(i["source"], i["target"]) for i in draw.items if i["kind"] == "edge"}
    assert expected <= actual, f"Missing original relationships: {expected-actual}"
    assert set(node_map.values()) <= set(draw.boxes), "Missing original modules."
    report = {
        "reference": str(REFERENCE),
        "preserved_relationships": len(expected),
        "preserved_modules": len(set(node_map.values())),
        "reference_relationships": sorted(expected),
        "explicit_loop_relationships": sorted(actual - expected),
    }
    (OUT / "relationship-check.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Reference: {len(expected)}/{len(expected)} relationships preserved; {len(actual-expected)} feedback/order edges added")


if __name__ == "__main__":
    build_layout()
    validate_reference()
    draw.write_drawio()
    draw.write_svg()
