"""Generate a single, editable architecture slide from one layout description."""

from pathlib import Path
import xml.etree.ElementTree as ET


OUT = Path(__file__).resolve().parent
WIDTH, HEIGHT = 1920, 1080
NAVY = "#1B2A4A"
GOLD = "#C9A84C"
INK = "#1A1A2E"
MUTED = "#4A5568"
LINE = "#D6DEE8"
BG = "#F7F8FA"
FONT = "Microsoft YaHei"
items = []
boxes = {}


def box(key, x, y, w, h, fill="#FFFFFF", stroke=LINE, rounded=True, line_width=1.5):
    item = dict(kind="box", key=key, x=x, y=y, w=w, h=h, fill=fill,
                stroke=stroke, rounded=rounded, line_width=line_width)
    items.append(item)
    boxes[key] = item


def label(key, value, x, y, w, h, size=18, color=INK, bold=False, align="left"):
    assert "\n" not in value, "Use separate editable text boxes for separate lines."
    items.append(dict(kind="text", key=key, value=value, x=x, y=y, w=w, h=h,
                      size=size, color=color, bold=bold, align=align))


def edge(key, source, target, points, color=NAVY, dashed=False, both=False):
    items.append(dict(kind="edge", key=key, source=source, target=target,
                      points=points, color=color, dashed=dashed, both=both))


def card(key, title, lines, x, y, w, h, title_size=24, fill="#FFFFFF", stroke=LINE):
    box(key, x, y, w, h, fill, stroke)
    label(key + "_title", title, x + 22, y + 14, w - 44, 36,
          size=title_size, bold=True, color=NAVY)
    for i, text in enumerate(lines):
        label(key + f"_body_{i}", text, x + 22, y + 53 + 28 * i,
              w - 44, 27, color=MUTED)


def build_layout():
    box("background", 0, 0, WIDTH, HEIGHT, BG, "none", False)
    box("header", 0, 0, WIDTH, 120, NAVY, "none", False)
    box("header_rule", 0, 120, WIDTH, 6, GOLD, "none", False)
    label("title", "VulnHunter 系统总体架构", 70, 26, 1400, 48, 30, "#FFFFFF", True)
    label("subtitle", "静态分析提供线索，动态验证形成证据，黑板驱动审计闭环。",
          70, 77, 1420, 30, 18, "#DCE4F1")
    label("header_tag", "SYSTEM ARCHITECTURE", 1500, 48, 350, 35, 14, "#DCE4F1", align="right")

    card("web", "Vue 3 Web 控制台",
         ["仓库 URL / Commit · 项目 / 函数", "数据集评测 · 运行观测"],
         70, 185, 405, 125)
    card("bridge", "FastAPI 服务桥与任务调度",
         ["HTTP API · 工作队列 · 并发控制 · 仓库检出",
          "审计 / 评测调度 · 暂停 / 恢复 · 指标汇总"],
         545, 185, 800, 125)
    card("model", "共享模型接入",
         ["OpenAI 兼容 API · 可配置推理", "主 Agent / executor / 结果整理"],
         1420, 185, 430, 125)

    box("static", 70, 340, 405, 470, "#FFFFFF")
    box("core", 545, 340, 800, 470, "#EEF2F8", "#B8C6DC", line_width=1.8)
    box("output", 1420, 340, 430, 470, "#FFFFFF")
    label("static_heading", "01  静态分析与代码上下文", 94, 354, 365, 37, 24, NAVY, True)
    label("core_heading", "02  审计与验证闭环", 570, 354, 540, 37, 24, NAVY, True)
    label("core_framework", "Deep Agents / LangGraph", 1128, 356, 194, 34, 14, MUTED, align="right")
    label("output_heading", "03  结构化输出", 1445, 354, 375, 37, 24, NAVY, True)

    card("files", "目标仓库上下文", ["只读文件检索 · 调用方约束"],
         95, 405, 355, 80, title_size=22)
    card("codeql", "CodeQL", ["查询执行 · 数据流分析"],
         95, 505, 355, 80, title_size=22)
    card("semgrep", "Semgrep", ["规则扫描 · 可疑代码定位"],
         95, 600, 355, 80, title_size=22)
    card("codebadger", "CodeBadger / Joern", ["CPG · 调用链 · 污点路径"],
         95, 695, 355, 80, title_size=22)

    card("main_agent", "主审计 Agent",
         ["读取上下文 · 更新漏洞假设", "规划验证 · 根据证据继续推理"],
         585, 405, 330, 140, fill="#FFFFFF", stroke="#A7B9D3")
    card("executor", "执行 Agent",
         ["executor · 接收验证计划", "容器工具 + 追加黑板工具"],
         995, 405, 300, 140, title_size=22, fill="#FFFFFF", stroke="#A7B9D3")
    card("blackboard", "追加式证据黑板",
         ["事实事件 · EvidenceRef", "按 ID 合并 · 每轮回注主 Agent"],
         585, 625, 330, 120, title_size=22, fill="#FFF9EB", stroke=GOLD)
    card("docker", "任务专属 Docker 容器",
         ["docker-mcp · /workspace", "环境准备 · PoC · 影响观察"],
         995, 625, 300, 120, title_size=22)
    label("core_note", "静态工具和动态验证按需调用，已确认事实指导后续审计。",
          580, 766, 720, 32, 18, MUTED)

    card("finalizer", "结构化结果整理",
         ["主 Agent 结论 + 黑板事实", "函数调用 → AuditAssessment"],
         1460, 405, 350, 145, title_size=24, fill="#EEF2F8", stroke="#B8C6DC")
    card("assessment", "结构化审计结果",
         ["verdict ∈ {0, 1}", "复现报告 · 步骤 · 证据 · PoC"],
         1460, 625, 350, 120, title_size=24, fill="#FFF9EB", stroke=GOLD)
    label("verdict_policy", "判定策略：攻击成功并观察到影响 → verdict = 1",
          1445, 766, 380, 32, 14, MUTED)

    box("support", 70, 860, 1780, 155, "#EEF1F5", LINE)
    label("support_heading", "运行支撑与可观测性", 95, 873, 1000, 32, 24, NAVY, True)
    card("journals", "任务与结果日志", ["审计任务 / 评测样例 · JSONL"],
         95, 915, 540, 85, title_size=22)
    card("traces", "Trace 观测与归档", ["Agent / 工具事件 · Token 用量"],
         665, 915, 540, 85, title_size=22)
    card("lifecycle", "运行与资源生命周期", ["并发限制 · 容器清理 · CPG / Joern 释放"],
         1235, 915, 590, 85, title_size=22)

    edge("web_api", "web", "bridge", [(475, 246), (545, 246)], both=True)
    label("api_label", "API", 485, 209, 52, 28, 14, MUTED, align="center")
    edge("audit_task", "bridge", "core", [(945, 310), (945, 340)])
    label("task_label", "审计调用", 965, 313, 110, 25, 14, MUTED)
    edge("static_tools", "static", "main_agent", [(475, 475), (585, 475)], both=True)
    label("static_label", "线索 / 查询", 484, 437, 96, 30, 14, MUTED, align="center")
    edge("delegation", "main_agent", "executor", [(915, 475), (995, 475)])
    label("delegation_label", "委派验证", 919, 437, 72, 30, 14, MUTED, align="center")
    edge("docker_mcp", "executor", "docker", [(1145, 545), (1145, 625)], both=True)
    label("docker_label", "docker-mcp", 1165, 565, 118, 28, 14, MUTED)
    edge("append_evidence", "executor", "blackboard",
         [(995, 505), (955, 505), (955, 587), (860, 587), (860, 625)], GOLD)
    label("append_label", "追加事实与证据", 775, 552, 166, 30, 14, "#80661E", align="right")
    edge("fact_feedback", "blackboard", "main_agent", [(710, 625), (710, 545)], GOLD)
    label("feedback_label", "事实回注", 611, 571, 90, 28, 14, "#80661E")
    edge("final_input", "core", "finalizer", [(1345, 475), (1460, 475)])
    label("final_input_label", "结论 + 黑板", 1348, 437, 108, 30, 14, MUTED, align="center")
    edge("validated_output", "finalizer", "assessment", [(1635, 550), (1635, 625)])
    label("validation_label", "字段校验", 1655, 569, 112, 30, 14, MUTED)
    edge("llm_core", "model", "core",
         [(1420, 246), (1380, 246), (1380, 367), (1345, 367)], MUTED, True)
    edge("llm_finalizer", "model", "output", [(1635, 310), (1635, 340)], MUTED, True)
    edge("trace_events", "core", "support", [(935, 810), (935, 860)], MUTED, True)
    label("trace_label", "回调事件", 957, 820, 112, 30, 14, MUTED)
    edge("result_archive", "output", "support", [(1635, 810), (1635, 860)], MUTED, True)
    label("archive_label", "结果归档", 1657, 820, 112, 30, 14, MUTED)

    # Use native rectangles: converters may snap floating edges to nearby shapes.
    box("legend_flow", 80, 1044, 53, 2, NAVY, "none", False)
    label("legend_flow_label", "调用 / 数据", 148, 1030, 180, 30, 14, MUTED)
    box("legend_feedback", 350, 1044, 53, 2, GOLD, "none", False)
    label("legend_feedback_label", "事实与证据回流", 418, 1030, 200, 30, 14, MUTED)
    for n, x in enumerate((665, 685, 705)):
        box(f"legend_support_{n}", x, 1044, 12, 2, MUTED, "none", False)
    label("legend_support_label", "模型接入 / 归档", 733, 1030, 260, 30, 14, MUTED)
    label("footer", "基于当前代码核对 · 2026-10-03", 1400, 1030, 450, 30, 14, MUTED, align="right")


def write_drawio():
    mxfile = ET.Element("mxfile", host="app.diagrams.net", version="26.0.0", type="device")
    diagram = ET.SubElement(mxfile, "diagram", id="vulnhunter-system", name="VulnHunter 系统架构")
    model = ET.SubElement(diagram, "mxGraphModel", dx="1920", dy="1080", grid="0", gridSize="10",
                          guides="1", tooltips="1", connect="1", arrows="1", fold="1", page="1",
                          pageScale="1", pageWidth=str(WIDTH), pageHeight=str(HEIGHT), math="0", shadow="0")
    root = ET.SubElement(model, "root")
    ET.SubElement(root, "mxCell", id="0")
    ET.SubElement(root, "mxCell", id="1", parent="0")
    for item in items:
        key, kind = item["key"], item["kind"]
        attrs = {"id": key, "parent": "1"}
        if kind == "box":
            attrs.update(vertex="1", value="", style=(
                f"rounded={int(item['rounded'])};arcSize=10;whiteSpace=wrap;html=1;"
                f"fillColor={item['fill']};strokeColor={item['stroke']};"
                f"strokeWidth={item['line_width']};shadow=0;"))
        elif kind == "text":
            attrs.update(vertex="1", value=item["value"], style=(
                "text;html=1;whiteSpace=wrap;strokeColor=none;fillColor=none;"
                f"align={item['align']};verticalAlign=middle;fontSize={item['size']};"
                f"fontColor={item['color']};fontStyle={int(item['bold'])};fontFamily={FONT};"
                "spacing=0;spacingLeft=0;spacingRight=0;spacingTop=0;spacingBottom=0;"))
        else:
            ports = ""
            for role, pt in (("exit", item["points"][0]), ("entry", item["points"][-1])):
                ref = item["source"] if role == "exit" else item["target"]
                if ref:
                    b = boxes[ref]
                    ports += (f"{role}X={(pt[0]-b['x'])/b['w']};"
                              f"{role}Y={(pt[1]-b['y'])/b['h']};{role}Dx=0;{role}Dy=0;"
                              f"{role}Perimeter=0;")
            attrs.update(edge="1", value="", style=(
                f"edgeStyle=none;rounded=0;html=1;strokeColor={item['color']};strokeWidth=2.2;"
                f"dashed={int(item['dashed'])};dashPattern=5 4;endArrow=block;endFill=1;"
                f"startArrow={'block' if item['both'] else 'none'};startFill=1;{ports}"))
            if item["source"]:
                attrs["source"] = item["source"]
            if item["target"]:
                attrs["target"] = item["target"]
        cell = ET.SubElement(root, "mxCell", **attrs)
        if kind != "edge":
            ET.SubElement(cell, "mxGeometry", x=str(item["x"]), y=str(item["y"]),
                          width=str(item["w"]), height=str(item["h"]), **{"as": "geometry"})
        else:
            geo = ET.SubElement(cell, "mxGeometry", relative="1", **{"as": "geometry"})
            for name, p in (("sourcePoint", item["points"][0]), ("targetPoint", item["points"][-1])):
                ET.SubElement(geo, "mxPoint", x=str(p[0]), y=str(p[1]), **{"as": name})
            if len(item["points"]) > 2:
                arr = ET.SubElement(geo, "Array", **{"as": "points"})
                for p in item["points"][1:-1]:
                    ET.SubElement(arr, "mxPoint", x=str(p[0]), y=str(p[1]))

    ids = [cell.get("id") for cell in root]
    assert len(ids) == len(set(ids))
    for cell in root:
        for endpoint in ("source", "target"):
            assert not cell.get(endpoint) or cell.get(endpoint) in ids
    for item in items:
        if item["kind"] != "edge":
            assert 0 <= item["x"] < WIDTH and 0 <= item["y"] < HEIGHT
            assert item["x"] + item["w"] <= WIDTH and item["y"] + item["h"] <= HEIGHT
    ET.indent(mxfile, space="  ")
    (OUT / "vulnhunter-architecture.drawio").write_bytes(
        ET.tostring(mxfile, encoding="utf-8", xml_declaration=True))
    print(f"Draw.io: 1 page, {len(ids)} cells, {sum(i['kind']=='text' for i in items)} editable text labels")


def write_svg():
    ns = "http://www.w3.org/2000/svg"
    ET.register_namespace("", ns)
    svg = ET.Element(f"{{{ns}}}svg", width=str(WIDTH), height=str(HEIGHT),
                     viewBox=f"0 0 {WIDTH} {HEIGHT}", role="img")
    title = ET.SubElement(svg, f"{{{ns}}}title")
    title.text = "VulnHunter 系统总体架构"
    desc = ET.SubElement(svg, f"{{{ns}}}desc")
    desc.text = "主审计 Agent 按需调用静态工具，委派 executor 在 Docker 容器中验证，通过追加式黑板回注事实，随后整理结构化结果。"
    defs = ET.SubElement(svg, f"{{{ns}}}defs")
    for c in (NAVY, GOLD, MUTED):
        ident = "arrow_" + c[1:]
        marker = ET.SubElement(defs, f"{{{ns}}}marker", id=ident, markerWidth="8", markerHeight="8",
                               refX="7", refY="4", orient="auto-start-reverse", markerUnits="userSpaceOnUse")
        ET.SubElement(marker, f"{{{ns}}}path", d="M 0 0 L 8 4 L 0 8 Z", fill=c)
    for item in items:
        if item["kind"] == "box":
            ET.SubElement(svg, f"{{{ns}}}rect", x=str(item["x"]), y=str(item["y"]),
                          width=str(item["w"]), height=str(item["h"]),
                          rx="10" if item["rounded"] else "0", fill=item["fill"],
                          stroke=item["stroke"], **{"stroke-width": str(item["line_width"])})
        elif item["kind"] == "text":
            align = item["align"]
            x = item["x"] if align == "left" else item["x"] + item["w"] * (0.5 if align == "center" else 1)
            text = ET.SubElement(svg, f"{{{ns}}}text", x=str(x),
                                 y=str(item["y"] + item["h"] / 2), fill=item["color"],
                                 **{"font-family": f"{FONT}, 微软雅黑, sans-serif",
                                    "font-size": str(item["size"]), "font-weight": "700" if item["bold"] else "400",
                                    "text-anchor": {"left": "start", "center": "middle", "right": "end"}[align],
                                    "dominant-baseline": "central"})
            text.text = item["value"]
        else:
            ident = "arrow_" + item["color"][1:]
            attrs = {"points": " ".join(f"{x},{y}" for x, y in item["points"]),
                     "fill": "none", "stroke": item["color"], "stroke-width": "2.2",
                     "stroke-linejoin": "round", "marker-end": f"url(#{ident})"}
            if item["dashed"]:
                attrs["stroke-dasharray"] = "5 4"
            if item["both"]:
                attrs["marker-start"] = f"url(#{ident})"
            ET.SubElement(svg, f"{{{ns}}}polyline", **attrs)
    ET.indent(svg, space="  ")
    (OUT / "vulnhunter-architecture.svg").write_bytes(
        ET.tostring(svg, encoding="utf-8", xml_declaration=True))


if __name__ == "__main__":
    build_layout()
    write_drawio()
    write_svg()
