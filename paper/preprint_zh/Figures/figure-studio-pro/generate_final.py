"""Render a source-grounded Figure Studio Pro line-art architecture diagram."""

from pathlib import Path
import xml.etree.ElementTree as ET

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties
from matplotlib.patches import Arc, Circle, Ellipse, FancyArrowPatch, FancyBboxPatch, Polygon, Rectangle


OUT = Path(__file__).resolve().parent.parent
FONT = FontProperties(fname=r"C:\Windows\Fonts\simhei.ttf")
INK = "#20272B"
MUTED = "#657176"
TEAL = "#287D73"
OCHRE = "#B77A35"


def txt(ax, x, y, value, size, *, color=INK, bold=False, ha="center"):
    ax.text(x, y, value, fontproperties=FONT, fontsize=size,
            fontweight="bold" if bold else "normal", color=color,
            ha=ha, va="center", zorder=9)


def ln(ax, x1, y1, x2, y2, *, color=INK, width=2.0, dashed=False):
    ax.plot([x1, x2], [y1, y2], color=color, linewidth=width,
            linestyle=(0, (6, 4)) if dashed else "solid",
            solid_capstyle="round", zorder=6)


def panel(ax, x, y, w, h, *, accent=None):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=15",
                                facecolor="white", edgecolor=INK, linewidth=2.2, zorder=4))
    if accent:
        ln(ax, x + 21, y + 4, x + w - 21, y + 4,
           color=accent, width=7.0)


def arrow(ax, x1, y1, x2, y2, *, color=INK, dashed=False):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>",
                                 mutation_scale=22, linewidth=2.5, color=color,
                                 linestyle=(0, (6, 4)) if dashed else "solid", zorder=7))


def document(ax, x, y, w, h):
    fold = 19
    points = [(x, y), (x + w - fold, y), (x + w, y + fold),
              (x + w, y + h), (x, y + h)]
    ax.add_patch(Polygon(points, closed=True, fill=False, edgecolor=INK,
                         linewidth=2.0, joinstyle="round", zorder=7))
    ln(ax, x + w - fold, y, x + w - fold, y + fold)
    ln(ax, x + w - fold, y + fold, x + w, y + fold)


def draw_input(ax):
    # One repository/database glyph and a target-function document.
    x, y = 95, 183
    ax.add_patch(Ellipse((x + 36, y), 72, 22, fill=False, edgecolor=INK, linewidth=2.2, zorder=7))
    for off in [0, 29, 58]:
        ax.add_patch(Arc((x + 36, y + off), 72, 22, theta1=0, theta2=180,
                         color=INK, linewidth=2.0, zorder=7))
    ln(ax, x, y, x, y + 58)
    ln(ax, x + 72, y, x + 72, y + 58)
    document(ax, 240, 166, 70, 90)
    txt(ax, 275, 219, "</>", 19, bold=True)
    ln(ax, 188, 213, 223, 213, color=MUTED, width=1.8)


def draw_audit(ax):
    ax.add_patch(Circle((637, 209), 37, fill=False, edgecolor=INK, linewidth=2.3, zorder=7))
    ln(ax, 663, 235, 691, 263, width=2.5)
    for yy, width in [(196, 52), (211, 70), (226, 43)]:
        ln(ax, 616, yy, 616 + width, yy, color=MUTED, width=1.5)
    ax.add_patch(Rectangle((728, 168), 93, 93, fill=False, edgecolor=INK,
                           linewidth=2.1, zorder=7))
    for yy in [188, 215, 242]:
        ln(ax, 741, yy, 749, yy + 7, width=1.7)
        ln(ax, 749, yy + 7, 762, yy - 7, width=1.7)
        ln(ax, 773, yy, 806, yy, color=MUTED, width=1.7)


def draw_executor(ax):
    ax.add_patch(FancyBboxPatch((1083, 164), 204, 86,
                                boxstyle="round,pad=0,rounding_size=5",
                                facecolor="white", edgecolor=INK,
                                linewidth=2.1, zorder=7))
    ln(ax, 1083, 189, 1287, 189, width=1.7)
    for xx in [1102, 1117, 1132]:
        ax.add_patch(Circle((xx, 177), 3, facecolor=MUTED, edgecolor="none", zorder=8))
    txt(ax, 1145, 219, ">_", 24, bold=True)
    ln(ax, 1182, 224, 1247, 224, color=MUTED, width=1.6)


def draw_report(ax):
    document(ax, 139, 451, 99, 111)
    for yy, width in [(486, 52), (505, 59), (524, 47)]:
        ln(ax, 154, yy, 154 + width, yy, width=1.8)
    ax.add_patch(Circle((253, 530), 30, facecolor="white", edgecolor=INK,
                        linewidth=2.2, zorder=8))
    ax.plot([239, 249, 269], [530, 540, 514], color=INK, linewidth=2.7,
            solid_capstyle="round", zorder=10)


def draw_blackboard(ax):
    ax.add_patch(Rectangle((1100, 460), 169, 115, fill=False, edgecolor=INK,
                           linewidth=2.1, zorder=7))
    for yy in [483, 510, 537, 564]:
        ax.add_patch(Circle((1124, yy), 4, facecolor="white", edgecolor=INK,
                            linewidth=1.7, zorder=8))
        ln(ax, 1142, yy, 1245 if yy != 564 else 1210, yy,
           color=MUTED, width=1.8)


def draw_tool_chip(ax, y, name, motif):
    ax.add_patch(FancyBboxPatch((555, y), 290, 49,
                                boxstyle="round,pad=0,rounding_size=8",
                                facecolor="white", edgecolor="#A9B1B5",
                                linewidth=1.5, zorder=6))
    if motif == "search":
        ax.add_patch(Circle((590, y + 23), 10, fill=False, edgecolor=INK,
                            linewidth=1.7, zorder=7))
        ln(ax, 597, y + 30, 606, y + 39, width=1.8)
    elif motif == "pattern":
        txt(ax, 591, y + 24, "{ }", 17, bold=True)
    else:
        for cx, cy in [(580, y + 15), (605, y + 20), (591, y + 36)]:
            ax.add_patch(Circle((cx, cy), 4, facecolor="white", edgecolor=INK,
                                linewidth=1.6, zorder=7))
        ln(ax, 583, y + 16, 602, y + 20, width=1.4)
        ln(ax, 602, y + 23, 593, y + 33, width=1.4)
        ln(ax, 586, y + 33, 580, y + 19, width=1.4)
    txt(ax, 710, y + 25, name, 18)


def render_figure():
    plt.rcParams["pdf.fonttype"] = 42
    fig, ax = plt.subplots(figsize=(14, 6.8), dpi=210)
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")
    ax.set_xlim(0, 1400)
    ax.set_ylim(680, 0)
    ax.axis("off")
    fig.subplots_adjust(left=0, right=1, top=1, bottom=0)

    panel(ax, 50, 80, 330, 220)
    panel(ax, 50, 385, 330, 220)
    panel(ax, 520, 60, 360, 550, accent=TEAL)
    panel(ax, 1020, 80, 330, 220, accent=OCHRE)
    panel(ax, 1020, 385, 330, 220)

    txt(ax, 215, 120, "仓库快照 + 目标函数", 21, bold=True)
    txt(ax, 215, 426, "结构化报告", 24, bold=True)
    txt(ax, 700, 105, "主审计代理", 26, bold=True)
    txt(ax, 700, 285, "仓库探索 · 漏洞假设", 17.5)
    txt(ax, 700, 357, "按需程序分析", 20, bold=True)
    txt(ax, 1185, 120, "执行代理", 24, bold=True)
    txt(ax, 1185, 269, "任务容器", 17.5, color=MUTED)
    txt(ax, 1185, 426, "事实黑板", 24, bold=True)

    draw_input(ax)
    draw_audit(ax)
    draw_executor(ax)
    draw_report(ax)
    draw_blackboard(ax)
    ln(ax, 550, 327, 850, 327, color="#B8C2C4", width=1.3)
    draw_tool_chip(ax, 391, "CodeQL", "search")
    draw_tool_chip(ax, 451, "Semgrep", "pattern")
    draw_tool_chip(ax, 511, "CodeBadger", "graph")

    arrow(ax, 380, 190, 520, 190)
    arrow(ax, 880, 190, 1020, 190)
    txt(ax, 950, 159, "验证计划", 15)
    arrow(ax, 1185, 300, 1185, 385)
    txt(ax, 1265, 344, "事实事件", 15)
    arrow(ax, 1020, 500, 880, 500, dashed=True)
    txt(ax, 950, 470, "回读事实", 15)
    arrow(ax, 520, 500, 380, 500)
    txt(ax, 450, 470, "结论", 15)

    fig.savefig(OUT / "VulnHunter-figure1-studio-pro.pdf", facecolor="white")
    fig.savefig(OUT / "VulnHunter-figure1-studio-pro.png", dpi=240,
                facecolor="white")
    plt.close(fig)


def render_drawio():
    mxfile = ET.Element("mxfile", {"host": "app.diagrams.net", "version": "24.7.17"})
    diagram = ET.SubElement(mxfile, "diagram", {"name": "VulnHunter Figure Studio Pro", "id": "vulnhunter-studio-pro-figure1"})
    model = ET.SubElement(diagram, "mxGraphModel", {
        "dx": "1400", "dy": "680", "grid": "1", "gridSize": "10", "guides": "1",
        "tooltips": "1", "connect": "1", "arrows": "1", "fold": "1",
        "page": "1", "pageScale": "1", "pageWidth": "1400", "pageHeight": "680",
        "background": "#FFFFFF",
    })
    root = ET.SubElement(model, "root")
    ET.SubElement(root, "mxCell", {"id": "0"})
    ET.SubElement(root, "mxCell", {"id": "1", "parent": "0"})
    seq = 2
    ids = {}

    def add_node(key, label, x, y, w, h, accent=""):
        nonlocal seq
        style = ("rounded=1;arcSize=12;whiteSpace=wrap;html=1;align=center;verticalAlign=middle;"
                 "fillColor=#FFFFFF;strokeColor=#20272B;strokeWidth=2;"
                 "fontColor=#20272B;fontSize=24;fontStyle=1;fontFamily=SimHei;")
        cell = ET.SubElement(root, "mxCell", {"id": str(seq), "value": label,
                                              "style": style, "vertex": "1", "parent": "1"})
        ids[key] = str(seq)
        seq += 1
        ET.SubElement(cell, "mxGeometry", {"x": str(x), "y": str(y),
                                             "width": str(w), "height": str(h), "as": "geometry"})
        if accent:
            cell = ET.SubElement(root, "mxCell", {"id": str(seq), "value": "",
                                                  "style": f"rounded=1;fillColor={accent};strokeColor=none;",
                                                  "vertex": "1", "parent": "1"})
            seq += 1
            ET.SubElement(cell, "mxGeometry", {"x": str(x + 20), "y": str(y + 3),
                                                 "width": str(w - 40), "height": "7", "as": "geometry"})

    add_node("input", "仓库快照 + 目标函数", 50, 80, 330, 220)
    add_node("report", "结构化报告", 50, 385, 330, 220)
    add_node("audit", "主审计代理<br>仓库探索 · 漏洞假设<br><br>按需程序分析<br>CodeQL · Semgrep · CodeBadger",
             520, 60, 360, 550, TEAL)
    add_node("executor", "执行代理<br>任务容器", 1020, 80, 330, 220, OCHRE)
    add_node("blackboard", "事实黑板", 1020, 385, 330, 220)

    def add_edge(source, target, label, *, dashed=False, exit_y=None, entry_y=None):
        nonlocal seq
        style = ("edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;"
                 "strokeColor=#20272B;strokeWidth=2;endArrow=block;"
                 f"dashed={int(dashed)};fontColor=#20272B;fontSize=16;"
                 f"exitY={exit_y if exit_y is not None else 0.5};"
                 f"entryY={entry_y if entry_y is not None else 0.5};")
        cell = ET.SubElement(root, "mxCell", {"id": str(seq), "value": label,
                                              "style": style, "edge": "1", "parent": "1",
                                              "source": ids[source], "target": ids[target]})
        seq += 1
        ET.SubElement(cell, "mxGeometry", {"relative": "1", "as": "geometry"})

    add_edge("input", "audit", "", exit_y=0.5, entry_y=0.236)
    add_edge("audit", "executor", "验证计划", exit_y=0.236, entry_y=0.5)
    add_edge("executor", "blackboard", "事实事件", exit_y=1, entry_y=0)
    add_edge("blackboard", "audit", "回读事实", dashed=True,
             exit_y=0.523, entry_y=0.8)
    add_edge("audit", "report", "结论", exit_y=0.8, entry_y=0.523)
    ET.indent(mxfile, space="  ")
    ET.ElementTree(mxfile).write(OUT / "VulnHunter-figure1-studio-pro.drawio",
                                 encoding="utf-8", xml_declaration=True)


if __name__ == "__main__":
    render_figure()
    render_drawio()
