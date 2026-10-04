"""Normalize the Draw.io MCP SVG export and produce vector PDF + PNG."""
from io import BytesIO
from pathlib import Path
import sys
import xml.etree.ElementTree as E

sys.path.insert(0, 'C:/Users/h2696/AppData/Local/Temp/vulnhunter-diagram-render-deps')
from svglib.svglib import svg2rlg, register_font
from reportlab.graphics import renderPDF
from pypdf import PdfReader
import pypdfium2 as pdfium

OUT = Path(__file__).parent
E.register_namespace('', 'http://www.w3.org/2000/svg')
E.register_namespace('xlink', 'http://www.w3.org/1999/xlink')
source_path = OUT / 'vulnhunter-architecture.drawio'
source = E.parse(source_path).getroot()
for page in list(source):
    if page.get('id') not in ('vulnhunter-paper-en', 'vulnhunter-paper-zh'):
        source.remove(page)
E.ElementTree(source).write(source_path, encoding='utf-8', xml_declaration=True)

for family, normal, bold, italic, bolditalic in [
    ('Times New Roman', 'times.ttf', 'timesbd.ttf', 'timesi.ttf', 'timesbi.ttf'),
    ('Microsoft YaHei', 'msyh.ttc', 'msyhbd.ttc', 'msyh.ttc', 'msyhbd.ttc'),
]:
    for weight, style, filename in [
        ('normal','normal',normal), ('bold','normal',bold),
        ('normal','italic',italic), ('bold','italic',bolditalic),
    ]:
        _, ok = register_font(family, str(Path('C:/Windows/Fonts') / filename),
                              weight=weight, style=style,
                              rlgFontName=family.replace(' ','')+'-'+weight+'-'+style)
        assert ok, (family, weight, style)

for lang in ('en','zh'):
    svg = OUT / f'vulnhunter-architecture-{lang}.svg'
    page = next(p for p in source if p.get('id') == f'vulnhunter-paper-{lang}')
    cells = {c.get('id'):c for c in page.iter('mxCell')}
    ids = [c.get('id') for c in page.iter('mxCell')]
    assert len(ids) == len(set(ids))
    for c in cells.values():
        for key in ('parent','source','target'):
            if c.get(key): assert c.get(key) in cells
    tree = E.parse(svg)
    count = [0]
    def normalize(element, cell_id=None):
        cell_id = element.get('data-cell-id',cell_id)
        if 'light-dark(' in element.get('style',''):
            element.attrib.pop('style',None)
        if element.tag.endswith('}text'):
            cell = cells[cell_id]
            value = cell.get('value','')
            assert value
            element.text = value
            for child in list(element): element.remove(child)
            style = cell.get('style','')
            flags = int(style.split('fontStyle=')[1].split(';')[0]) if 'fontStyle=' in style else 0
            element.set('font-family','Microsoft YaHei' if lang == 'zh' else 'Times New Roman')
            element.set('font-weight','bold' if flags & 1 else 'normal')
            element.set('font-style','italic' if flags & 2 else 'normal')
            count[0] += 1
        for child in element: normalize(child,cell_id)
    normalize(tree.getroot())
    tree.getroot().attrib.pop('style',None)
    assert not any(e.tag.endswith('foreignObject') for e in tree.iter())
    tree.write(svg,encoding='utf-8',xml_declaration=True)
    d = svg2rlg(BytesIO(E.tostring(tree.getroot(),encoding='utf-8')))
    assert d is not None
    pdf = svg.with_suffix('.pdf')
    renderPDF.drawToFile(d,str(pdf))
    doc = pdfium.PdfDocument(pdf)
    image = doc[0].render(scale=4).to_pil()
    image.convert('RGB').save(svg.with_suffix('.png'),dpi=(384,384))
    doc.close()
    check = PdfReader(pdf)
    assert len(check.pages) == 1
    assert 'AuditAssessment' in check.pages[0].extract_text()
    assert not check.pages[0].get('/Resources',{}).get('/XObject'), 'Expected vector PDF'
    expected = sum(bool(c.get('value')) and c.get('vertex')=='1' for c in cells.values())
    assert count[0] == expected, (count[0],expected)
    print(f'{lang}: {len(cells)} cells, {count[0]} verified labels, {image.size}, vector PDF {pdf.stat().st_size} bytes')
