"""Generate the editable and publication versions of Figure 1."""

from pathlib import Path
import xml.etree.ElementTree as ET

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Circle


HERE = Path(__file__).resolve().parent
FONT = FontProperties(fname=r"C:\Windows\Fonts\simhei.ttf")
NAVY = "#172B45"
MUTED = "#52647B"
LINE = "#71839A"
BLUE = "#2E62AB"
AMBER = "#B66A19"
PURPLE = "#7253A1"
GREEN = "#287966"

BOXES = [
    dict(id="input", x=455, y=28, w=290, h=72, title="任务输入", detail="仓库快照 + 目标函数", fill="#F3F6FA", stroke="#90A2B8", badge="01", accent=NAVY),
    dict(id="tools", x=45, y=150, w=280, h=180, title="按需程序分析", detail="CodeQL · Semgrep · CodeBadger", fill="#F4F7FB", stroke="#A8B8CC", badge="工具", accent=BLUE),
    dict(id="audit", x=445, y=150, w=310, h=124, title="主审计代理", detail="仓库探索 · 漏洞假设\n制定动态验证计划", fill="#EBF3FF", stroke="#6090CB", badge="02", accent=BLUE),
    dict(id="executor", x=865, y=150, w=290, h=124, title="执行代理", detail="任务专属 Docker 容器\n构造输入并观察运行", fill="#FFF4E8", stroke="#D7A266", badge="03", accent=AMBER),
    dict(id="blackboard", x=865, y=340, w=290, h=105, title="追加式事实黑板", detail="事件去重 · 可选证据引用", fill="#F3EEFB", stroke="#A28BC8", badge="04", accent=PURPLE),
    dict(id="report", x=445, y=340, w=310, h=105, title="结构化结论与报告", detail="0/1 判定 · 阳性报告附证据", fill="#EAF6F1", stroke="#72AA99", badge="05", accent=GREEN),
]


def draw_route(ax, points, *, color=LINE, dashed=False, double=False, width=2.2):
    for start, end in zip(points[:-2], points[1:-1]):
        ax.plot([start[0], end[0]], [start[1], end[1]], color=color,
                linewidth=width, linestyle=(0, (5, 4)) if dashed else "solid",
                solid_capstyle="round", zorder=1)
    start, end = points[-2:]
    ax.add_patch(FancyArrowPatch(start, end, arrowstyle="-|>", mutation_scale=15,
                                 linewidth=width, color=color,
                                 linestyle=(0, (5, 4)) if dashed else "solid", zorder=1))
    if double:
        start, end = points[:2]
        ax.add_patch(FancyArrowPatch(end, start, arrowstyle="-|>", mutation_scale=15,
                                     linewidth=width, color=color, zorder=1))


def draw_box(ax, box):
    x, y, w, h = (box[k] for k in ("x", "y", "w", "h"))
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=17",
                                facecolor=box["fill"], edgecolor=box["stroke"],
                                linewidth=1.6, zorder=3))
    ax.plot([x + 17, x + w - 17], [y + 2, y + 2], color=box["accent"],
            linewidth=4.3, solid_capstyle="round", zorder=4)
    if box["id"] == "tools":
        ax.text(x + 22, y + 43, box["title"], fontproperties=FONT, fontsize=19,
                fontweight="bold", color=NAVY, va="center", zorder=5)
        for i, label in enumerate(["CodeQL", "Semgrep", "CodeBadger"]):
            py = y + 77 + i * 33
            ax.add_patch(FancyBboxPatch((x + 19, py), w - 38, 27,
                                        boxstyle="round,pad=0,rounding_size=8",
                                        facecolor="white", edgecolor="#D7E0EA", linewidth=0.9, zorder=4))
            ax.text(x + w / 2, py + 14, label, fontsize=14.5, color=BLUE,
                    ha="center", va="center", zorder=5)
    else:
        center = x + w / 2
        title_y = y + (31 if h <= 105 else 41)
        ax.text(center, title_y, box["title"], fontproperties=FONT, fontsize=20,
                fontweight="bold", color=NAVY, ha="center", va="center", zorder=5)
        detail_y = y + (57 if h <= 105 else 78)
        ax.text(center, detail_y, box["detail"], fontproperties=FONT, fontsize=14.3,
                linespacing=1.55, color=MUTED, ha="center", va="center", zorder=5)
    bx, by = x + w - 24, y + 19
    ax.add_patch(Circle((bx, by), 16, facecolor=box["accent"], edgecolor="white",
                        linewidth=1.2, zorder=6))
    ax.text(bx, by, box["badge"], fontproperties=FONT,
            fontsize=10.2 if box["badge"] == "工具" else 10.8,
            fontweight="bold", color="white", ha="center", va="center", zorder=7)


def render_pdf_and_png():
    plt.rcParams["pdf.fonttype"] = 42
    fig, ax = plt.subplots(figsize=(12, 4.8), dpi=200)
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")
    ax.set_xlim(0, 1200)
    ax.set_ylim(480, 0)
    ax.axis("off")
    fig.subplots_adjust(left=0.005, right=0.995, top=0.99, bottom=0.01)

    draw_route(ax, [(600, 100), (600, 150)], color=BLUE)
    draw_route(ax, [(325, 216), (445, 216)], color=BLUE, double=True)
    draw_route(ax, [(755, 214), (865, 214)], color=AMBER)
    draw_route(ax, [(1010, 274), (1010, 340)], color=PURPLE)
    draw_route(ax, [(865, 392), (810, 392), (810, 304), (713, 304), (713, 274)],
               color=PURPLE, dashed=True, width=2)
    draw_route(ax, [(555, 274), (555, 340)], color=GREEN)

    for box in BOXES:
        draw_box(ax, box)

    labels = [
        (385, 193, "查询/线索", BLUE),
        (809, 190, "验证计划", AMBER),
        (1047, 311, "事实与观察", PURPLE),
        (765, 318, "事实回读", PURPLE),
        (577, 307, "综合判断", GREEN),
    ]
    for x, y, label, color in labels:
        ax.text(x, y, label, fontproperties=FONT, fontsize=11.8,
                color=color, ha="center", va="center", zorder=8)

    fig.savefig(HERE / "VulnHunter-figure1.pdf", facecolor="white")
    fig.savefig(HERE / "VulnHunter-figure1.png", dpi=240, facecolor="white")
    plt.close(fig)


def render_drawio():
    mxfile = ET.Element("mxfile", {"host": "app.diagrams.net", "version": "24.7.17"})
    diagram = ET.SubElement(mxfile, "diagram", {"name": "VulnHunter 审计流程", "id": "vulnhunter-figure1"})
    model = ET.SubElement(diagram, "mxGraphModel", {
        "dx": "1200", "dy": "480", "grid": "1", "gridSize": "10", "guides": "1",
        "tooltips": "1", "connect": "1", "arrows": "1", "fold": "1",
        "page": "1", "pageScale": "1", "pageWidth": "1200", "pageHeight": "480",
        "background": "#FFFFFF",
    })
    root = ET.SubElement(model, "root")
    ET.SubElement(root, "mxCell", {"id": "0"})
    ET.SubElement(root, "mxCell", {"id": "1", "parent": "0"})
    id_counter = 2
    node_ids = {}

    def vertex(value, x, y, w, h, style):
        nonlocal id_counter
        cell_id = str(id_counter)
        id_counter += 1
        cell = ET.SubElement(root, "mxCell", {"id": cell_id, "value": value,
                                                "style": style, "vertex": "1", "parent": "1"})
        ET.SubElement(cell, "mxGeometry", {"x": str(x), "y": str(y),
                                                "width": str(w), "height": str(h), "as": "geometry"})
        return cell_id

    for box in BOXES:
        detail = box["detail"].replace("\n", "<br>")
        label = (f'<div style="font-size:20px;font-weight:700;color:{NAVY}">{box["title"]}</div>'
                 + ("" if box["id"] == "tools" else
                    f'<div style="font-size:14px;color:{MUTED};line-height:1.5">{detail}</div>'))
        style = ("rounded=1;arcSize=16;whiteSpace=wrap;html=1;align=center;"
                 f"verticalAlign={'top' if box['id'] == 'tools' else 'middle'};"
                 f"fillColor={box['fill']};strokeColor={box['stroke']};strokeWidth=2;"
                 f"fontColor={NAVY};fontSize=18;fontFamily=Noto Sans SC;"
                 f"spacingTop={'28' if box['id'] == 'tools' else '10'};")
        node_ids[box["id"]] = vertex(label, box["x"], box["y"], box["w"], box["h"], style)
        vertex("", box["x"] + 17, box["y"] + 2, box["w"] - 34, 4,
               f"rounded=1;arcSize=50;fillColor={box['accent']};strokeColor=none;")
        vertex(box["badge"], box["x"] + box["w"] - 40, box["y"] + 3, 32, 32,
               "ellipse;whiteSpace=wrap;html=0;align=center;verticalAlign=middle;"
               f"fillColor={box['accent']};strokeColor=#FFFFFF;strokeWidth=1;"
               "fontColor=#FFFFFF;fontSize=11;fontStyle=1;")

    for i, label in enumerate(["CodeQL", "Semgrep", "CodeBadger"]):
        vertex(label, 64, 227 + i * 33, 242, 27,
               "rounded=1;arcSize=12;whiteSpace=wrap;html=0;align=center;verticalAlign=middle;"
               f"fillColor=#FFFFFF;strokeColor=#D7E0EA;fontColor={BLUE};fontSize=14;")

    def edge(source, target, value="", dashed=False, both=False, points=None):
        nonlocal id_counter
        style = ("edgeStyle=orthogonalEdgeStyle;rounded=1;html=0;"
                 f"strokeColor={PURPLE if dashed else LINE};strokeWidth=2;"
                 f"dashed={1 if dashed else 0};endArrow=block;"
                 f"startArrow={'block' if both else 'none'};fontSize=12;fontColor={MUTED};")
        cell = ET.SubElement(root, "mxCell", {"id": str(id_counter), "value": value,
                                              "style": style, "edge": "1", "parent": "1",
                                              "source": node_ids[source], "target": node_ids[target]})
        id_counter += 1
        geom = ET.SubElement(cell, "mxGeometry", {"relative": "1", "as": "geometry"})
        if points:
            arr = ET.SubElement(geom, "Array", {"as": "points"})
            for x, y in points:
                ET.SubElement(arr, "mxPoint", {"x": str(x), "y": str(y)})

    edge("input", "audit")
    edge("tools", "audit", "查询 / 线索", both=True)
    edge("audit", "executor", "验证计划")
    edge("executor", "blackboard", "事实与观察")
    edge("blackboard", "audit", "事实回读", dashed=True,
         points=[(810, 392), (810, 304), (713, 304)])
    edge("audit", "report", "综合判断")

    ET.indent(mxfile, space="  ")
    ET.ElementTree(mxfile).write(HERE / "VulnHunter-figure1.drawio",
                                 encoding="utf-8", xml_declaration=True)


if __name__ == "__main__":
    render_pdf_and_png()
    render_drawio()
