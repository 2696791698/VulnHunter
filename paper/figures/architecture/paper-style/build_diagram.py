"""Editable paper figure; layout and colors follow the supplied references."""
from pathlib import Path
import json
import xml.etree.ElementTree as E

OUT = Path(__file__).parent


def build(lang):
    zh = lang == 'zh'
    font = 'Microsoft YaHei' if zh else 'Times New Roman'
    root = E.Element('root')
    E.SubElement(root, 'mxCell', id='0')
    E.SubElement(root, 'mxCell', id='1', parent='0')
    seq = 2
    backgrounds, vertices, lines, texts = [], [], [], []

    def vertex(value, x, y, w, h, style, dest=vertices):
        nonlocal seq
        cell_id = str(seq)
        seq += 1
        c = E.Element('mxCell', id=cell_id, value=value, style=style, vertex='1', parent='1')
        E.SubElement(c, 'mxGeometry', x=str(x), y=str(y), width=str(w), height=str(h), **{'as': 'geometry'})
        dest.append(c)
        return cell_id

    def text(value, x, y, w, h=17, size=11, bold=False, color='#272D39', align='center', italic=False):
        style = (f'shape=label;html=0;whiteSpace=nowrap;overflow=visible;strokeColor=none;fillColor=none;'
                 f'fontFamily={font};fontSize={size};fontStyle={int(bold) + 2 * int(italic)};'
                 f'fontColor={color};align={align};verticalAlign=middle;spacing=0;')
        return vertex(value, x, y, w, h, style, texts)

    def card(x, y, w, h, fill, stroke, dashed=False, dest=vertices, radius=20):
        style = (f'rounded=1;arcSize={radius};html=0;fillColor={fill};strokeColor={stroke};strokeWidth=1.1;'
                 f'{"dashed=1;dashPattern=6 4;" if dashed else ""}')
        return vertex('', x, y, w, h, style, dest)

    def row(value, x, y, w, h=25, size=11):
        card(x, y, w, h, '#FAFCFE', 'none', radius=14)
        text(value, x+2, y+2, w-4, h-4, size)

    def arrow(source, target, ports, color='#6888BA', fill='#DDE7F5', points=(), both=False, width=4):
        nonlocal seq
        cell_id = str(seq)
        seq += 1
        style = (f'shape=flexArrow;edgeStyle=orthogonalEdgeStyle;rounded=0;html=0;'
                 f'strokeColor={color};fillColor={fill};strokeWidth=0.9;width={width};'
                 f'endArrow=block;endSize={4 if both else 7};endWidth={10 if both else 13};'
                 f'startArrow={"block" if both else "none"};startSize={4 if both else 7};startWidth={10 if both else 13};'
                 f'exitX={ports[0]};exitY={ports[1]};entryX={ports[2]};entryY={ports[3]};'
                 'exitPerimeter=1;entryPerimeter=1;')
        c = E.Element('mxCell', id=cell_id, value='', style=style, edge='1', parent='1', source=source, target=target)
        g = E.SubElement(c, 'mxGeometry', relative='1', **{'as':'geometry'})
        if points:
            a=E.SubElement(g, 'Array', **{'as':'points'})
            for x,y in points: E.SubElement(a,'mxPoint',x=str(x),y=str(y))
        lines.append(c)

    # Major regions: input, an iterative audit runtime, and output.
    card(202,40,424,363,'#F7F8FA','#9EAABD',True,backgrounds,14)
    inp=card(40,60,142,343,'#EFF4ED','#ADBFAB',dest=backgrounds,radius=24)
    out=card(650,60,118,343,'#EBF1E8','#A9BCA2',dest=backgrounds,radius=24)
    text('VulnHunter Runtime',216,49,270,24,17,True,align='left')
    text('共用 LLM' if zh else 'Shared LLM',527,43,83,16,8.5,False,color='#536277')

    # Small editable Git symbol (diamond, branches, and three circles).
    vertex('',53,81,28,28,'shape=rhombus;fillColor=#465648;strokeColor=none;')
    vertex('',62,91,2,11,'fillColor=#FFFFFF;strokeColor=none;')
    vertex('',65,91,9,2,'fillColor=#FFFFFF;strokeColor=none;rotation=45;')
    for x,y in [(61,89),(61,100),(71,98)]:
        vertex('',x,y,5,5,'ellipse;fillColor=#FFFFFF;strokeColor=none;')
    text('审计' if zh else 'Audit',85,76,86,22,16,True)
    text('任务' if zh else 'Task',85,97,86,22,16,True)
    card(50,142,122,126,'#DFE9D9','#BACDB3',radius=23)
    text('审计范围' if zh else 'Audit Scope',56,151,110,22,13,True)
    text('固定提交版本' if zh else 'Pinned revision',55,179,112,19,11)
    text('目标文件 / 函数' if zh else 'Target file / function',53,209,116,19,10.5)
    text('审计指令' if zh else 'Audit instruction',55,239,112,19,11)

    # Native folder and code-document icons.
    vertex('',53,299,24,18,'shape=folder;tabWidth=9;tabHeight=5;fillColor=#E6C988;strokeColor=#6F715E;strokeWidth=0.9;')
    text('仓库' if zh else 'Repository',84,289,85,18,12)
    text('快照' if zh else 'snapshot',84,307,85,18,12)
    vertex('',55,343,20,27,'shape=note;size=6;fillColor=#DDE6F2;strokeColor=#566B88;strokeWidth=0.9;')
    text('</>',55,349,20,12,7.5,True,color='#3D5D84')
    text('目标' if zh else 'Target',84,339,85,18,12)
    text('函数' if zh else 'function',84,357,85,18,12)

    # Main audit agent and its external static tools.
    main=card(215,95,190,143,'#DBE5F3','#A4B5CD',radius=20)
    text('主审计 Agent' if zh else 'Audit Agent',223,101,174,24,16,True)
    text('LLM 驱动的安全推理' if zh else '(LLM-guided security reasoning)',221,124,178,16,9.5)
    for label,y in zip(
        ['读取仓库上下文','更新漏洞假设','制定动态验证计划'] if zh else
        ['Read repository context','Refine vulnerability hypotheses','Plan dynamic verification'],
        [147,176,205]):
        row(label,224,y,172,25,11 if zh else 10.5)
    static=card(215,278,190,105,'#E5EDF7','#A4B5CD',radius=24)
    text('静态分析工具（MCP）' if zh else 'Static Analysis (MCP)',221,286,178,22,13,True)
    row('CodeQL  ·  Semgrep',224,315,172,24,12)
    row('CodeBadger / Joern CPG',224,344,172,26,11.5)

    # Executor keeps execution behind Docker MCP; the blackboard is state.
    exe=card(445,95,170,165,'#F3E5D5','#C1A789',radius=24)
    text('执行 Agent' if zh else 'Executor',453,101,154,24,16,True,color='#49392D')
    text('容器执行子代理' if zh else '(container subagent)',451,124,158,16,9.5,color='#675242')
    card(455,146,150,102,'#FFFCF6','#D9C6B0',radius=14)
    text('Docker MCP',461,151,138,21,12,True,color='#49392D')
    text('准备运行环境' if zh else 'Environment setup',461,177,138,17,11)
    text('Shell / PoC 执行' if zh else 'Shell / PoC execution',461,198,138,17,11)
    text('记录实际安全影响' if zh else 'Observed security impact',459,220,142,17,10.5)
    board=card(445,300,170,83,'#E8DFEF','#B6A2C7',radius=24)
    text('证据黑板' if zh else 'Evidence Blackboard',451,305,158,22,14,True,color='#403448')
    row('追加事实事件' if zh else 'Append-only fact events',454,335,152,20,11)
    row('证据引用' if zh else 'Evidence references',454,359,152,17,10.5)

    # Output aggregates final text and blackboard facts into the actual schema.
    text('审计输出' if zh else 'Audit Output',656,73,106,23,15,True,color='#344C35')
    text('AuditAssessment',656,97,106,18,10,color='#526452')
    card(660,127,98,77,'#FAFDF8','#C9D7C2',radius=14)
    text('二值判定' if zh else 'Binary Verdict',665,134,88,21,12,True)
    text('1：有漏洞' if zh else '1: Vulnerable',664,159,90,17,10.5)
    text('0：无漏洞' if zh else '0: Non-vulnerable',663,180,92,17,9.5)
    text('仅阳性结论需要报告' if zh else '(for positive verdicts)',653,213,112,18,8.5,italic=True)
    card(660,237,98,129,'#FAFDF8','#C9D7C2',radius=14)
    text('复现报告' if zh else 'Reproduction',664,242,90,18,12,True)
    if not zh: text('Report',664,258,90,18,12,True)
    for label,y in zip(
        ['漏洞位置','步骤与 PoC','观察到的影响','证据引用'] if zh else
        ['Location','Steps & PoC','Observed effect','Evidence'],
        [282,302,322,342]):
        text(label,664,y,90,17,10.5)
    text('结构化结果整理' if zh else 'Structured finalization',652,378,114,19,9,color='#526452')

    arrow(inp,main,[1,.52,0,.44],color='#7B9F65',fill='#E3EEDB',points=[(194,238.36),(194,157.92)])
    arrow(main,static,[.5,1,.5,0],both=True,width=3)
    text('查询 / 静态线索' if zh else 'Queries / findings',322,246,94,18,9,color='#536B8A')
    arrow(main,exe,[1,.51,0,.45],points=[(425,167.93),(425,169.25)])
    text('验证计划' if zh else 'Plan',407,143,36,18,8.5,color='#536B8A')
    arrow(exe,board,[.5,1,.5,0],color='#9A82B0',fill='#EAE2F2')
    text('追加证据' if zh else 'Append evidence',547,270,78,19,9,color='#6B547E')
    arrow(board,main,[0,.55,1,.86],color='#8C78A7',fill='#EAE2F2',points=[(426,345.65),(426,217.98)],width=3)
    arrow(main,out,[.75,0,0,.17],points=[(357.5,79),(637,79),(637,118.31)],width=3)
    text('最终结论' if zh else 'Final conclusion',476,64,130,14,9,color='#536B8A')
    arrow(board,out,[1,.55,0,.83],color='#8C78A7',fill='#EAE2F2',points=[(637,345.65),(637,344.69)],width=3)
    text('静态工具与动态验证按需调用' if zh else 'Static tools and dynamic checks are invoked on demand.',202,416,424,17,9,color='#697687',italic=True)

    for c in backgrounds + lines + vertices + texts: root.append(c)
    m=E.Element('mxGraphModel',dx='800',dy='450',grid='1',gridSize='10',guides='1',tooltips='1',connect='1',arrows='1',fold='1',page='1',pageScale='1',pageWidth='800',pageHeight='450',math='0',shadow='0',background='#FFFFFF')
    m.append(root)
    ids=[c.get('id') for c in root]
    assert len(ids)==len(set(ids))
    for c in root:
        for a in ('parent','source','target'):
            if c.get(a): assert c.get(a) in ids
    return E.tostring(m,encoding='unicode')


if __name__ == '__main__':
    print(json.dumps({lang:build(lang) for lang in ('zh','en')},ensure_ascii=True))
