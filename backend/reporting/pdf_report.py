import io
import logging
from datetime import datetime, timezone
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak as RLPageBreak, HRFlowable, KeepTogether
)
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfgen import canvas
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate

logger = logging.getLogger(__name__)

# ── Brand Palette ────────────────────────────────────────────────────────────
NAVY        = colors.HexColor('#0D1B2A')
NAVY_LIGHT  = colors.HexColor('#1B2A4A')
GOLD        = colors.HexColor('#D4AC0D')
GOLD_LIGHT  = colors.HexColor('#F0C93A')
RED         = colors.HexColor('#C0392B')
RED_LIGHT   = colors.HexColor('#F1948A')
GREEN       = colors.HexColor('#1E8449')
GREEN_LIGHT = colors.HexColor('#A9DFBF')
ORANGE      = colors.HexColor('#D35400')
ORANGE_LIGHT= colors.HexColor('#FAD7A0')
BLUE_ACCENT = colors.HexColor('#2E86C1')
GREY_BG     = colors.HexColor('#F4F6F9')
GREY_LINE   = colors.HexColor('#D5D8DC')
GREY_TEXT   = colors.HexColor('#566573')
WHITE       = colors.white
BLACK       = colors.HexColor('#1A1A1A')


def _score_color(score):
    if score < 50:   return RED
    if score < 70:   return ORANGE
    if score < 85:   return GOLD
    return GREEN


def _status_label(label):
    mapping = {
        'Quantum Vulnerable': 'VULNERABLE',
        'PQC Ready':          'PQC READY',
        'Fully Quantum Safe': 'SECURE',
    }
    return mapping.get(label, 'UNKNOWN')


def _status_color(label):
    mapping = {
        'Quantum Vulnerable': RED,
        'PQC Ready':          ORANGE,
        'Fully Quantum Safe': GREEN,
    }
    return mapping.get(label, GREY_TEXT)


def _score_bar_html(score, bar_len=12):
    filled = int(round(score / 100 * bar_len))
    empty  = bar_len - filled
    col    = _score_color(score)
    hex_   = col.hexval() if hasattr(col, 'hexval') else '#888888'
    bar    = f'<font color="{hex_}">{"█" * filled}</font><font color="#D5D8DC">{"░" * empty}</font>'
    return bar


# ── Page decorators ──────────────────────────────────────────────────────────

class NumberedCanvas(canvas.Canvas):
    """Adds page numbers and a subtle header/footer rule to every page."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._pages = []

    def showPage(self):
        self._pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._pages)
        for i, page_dict in enumerate(self._pages, 1):
            self.__dict__.update(page_dict)
            self._draw_chrome(i, total)
            super().showPage()
        super().save()

    def _draw_chrome(self, page_num, total):
        w, h = A4
        # ── footer rule
        self.setStrokeColor(GOLD)
        self.setLineWidth(1.5)
        self.line(1.8*cm, 1.6*cm, w - 1.8*cm, 1.6*cm)

        # ── footer text
        self.setFillColor(GREY_TEXT)
        self.setFont('Helvetica', 7)
        self.drawString(1.8*cm, 1.1*cm, 'Q-SHIELD  |  QUANTUM-PROOF SYSTEMS SCANNER  |  CONFIDENTIAL')
        self.drawRightString(w - 1.8*cm, 1.1*cm, f'Page {page_num} of {total}')

        # ── top accent line (skip cover)
        if page_num > 1:
            self.setStrokeColor(NAVY_LIGHT)
            self.setLineWidth(3)
            self.line(0, h, w, h)


# ── Style factory ────────────────────────────────────────────────────────────

def _build_styles():
    base = getSampleStyleSheet()

    def P(name, **kw):
        return ParagraphStyle(name, **kw)

    return {
        # cover
        'cover_brand':  P('cover_brand',  fontSize=11, textColor=GOLD,       alignment=TA_CENTER, fontName='Helvetica-Bold', spaceAfter=2),
        'cover_title':  P('cover_title',  fontSize=38, textColor=WHITE,       alignment=TA_CENTER, fontName='Helvetica-Bold', leading=44),
        'cover_sub':    P('cover_sub',    fontSize=13, textColor=GOLD_LIGHT,  alignment=TA_CENTER, fontName='Helvetica',      spaceAfter=4),
        'cover_report': P('cover_report', fontSize=10, textColor=GREY_LINE,   alignment=TA_CENTER, fontName='Helvetica',      spaceAfter=2),
        'cover_score':  P('cover_score',  fontSize=72, textColor=WHITE,       alignment=TA_CENTER, fontName='Helvetica-Bold', leading=78),
        'cover_slbl':   P('cover_slbl',   fontSize=10, textColor=GOLD,        alignment=TA_CENTER, fontName='Helvetica-Bold', spaceAfter=0),
        'cover_date':   P('cover_date',   fontSize=8,  textColor=GREY_LINE,   alignment=TA_CENTER, fontName='Helvetica'),

        # section headers
        'section_h1':   P('section_h1',   fontSize=16, textColor=NAVY,       fontName='Helvetica-Bold', spaceBefore=14, spaceAfter=6, borderPad=0),
        'section_h2':   P('section_h2',   fontSize=12, textColor=NAVY_LIGHT, fontName='Helvetica-Bold', spaceBefore=10, spaceAfter=4),
        'section_tag':  P('section_tag',  fontSize=8,  textColor=WHITE,       fontName='Helvetica-Bold', alignment=TA_CENTER),

        # body
        'body':         P('body',         fontSize=9,  textColor=BLACK,       fontName='Helvetica', leading=14, spaceAfter=4),
        'body_sm':      P('body_sm',      fontSize=8,  textColor=GREY_TEXT,   fontName='Helvetica', leading=12),
        'table_hdr':    P('table_hdr',    fontSize=8,  textColor=WHITE,       fontName='Helvetica-Bold', alignment=TA_CENTER),
        'table_cell':   P('table_cell',   fontSize=8,  textColor=BLACK,       fontName='Helvetica', alignment=TA_LEFT),
        'table_cell_c': P('table_cell_c', fontSize=8,  textColor=BLACK,       fontName='Helvetica', alignment=TA_CENTER),
        'rec_title':    P('rec_title',    fontSize=9,  textColor=BLACK,       fontName='Helvetica-Bold', spaceAfter=1),
        'rec_body':     P('rec_body',     fontSize=8,  textColor=GREY_TEXT,   fontName='Helvetica', leading=12, spaceAfter=6),
        'caption':      P('caption',      fontSize=7,  textColor=GREY_TEXT,   fontName='Helvetica-Oblique', alignment=TA_CENTER, spaceAfter=6),
    }


# ── Helper builders ──────────────────────────────────────────────────────────

def _section_header(title, styles, tag=None):
    """Returns a list of flowables for a bold section header with optional pill tag."""
    items = []
    items.append(HRFlowable(width='100%', thickness=2, color=NAVY, spaceAfter=4, spaceBefore=6))
    items.append(Paragraph(title, styles['section_h1']))
    return items


def _pill(text, bg_color, styles):
    """A small coloured pill table for status labels."""
    t = Table([[Paragraph(text, styles['section_tag'])]], colWidths=[2.2*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), bg_color),
        ('ROUNDEDCORNERS', [4, 4, 4, 4]),
        ('TOPPADDING',  (0,0), (-1,-1), 2),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
        ('LEFTPADDING',  (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    return t


def _cover_metric_table(metrics, styles):
    """4-up metric card grid for the cover page."""
    # metrics = [(label, value, color), ...]
    card_data = []
    row = []
    for i, (lbl, val, col) in enumerate(metrics):
        inner = Table([
            [Paragraph(str(val), ParagraphStyle('mv', fontSize=22, textColor=col,
                        fontName='Helvetica-Bold', alignment=TA_CENTER))],
            [Paragraph(lbl,      ParagraphStyle('ml', fontSize=8,  textColor=GREY_TEXT,
                        fontName='Helvetica-Bold', alignment=TA_CENTER))],
        ], colWidths=[4*cm])
        inner.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), WHITE),
            ('BOX',        (0,0), (-1,-1), 0.5, GREY_LINE),
            ('TOPPADDING',    (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ]))
        row.append(inner)
        if len(row) == 4:
            card_data.append(row)
            row = []
    if row:
        while len(row) < 4:
            row.append('')
        card_data.append(row)

    t = Table(card_data, colWidths=[4.3*cm]*4, hAlign='CENTER')
    t.setStyle(TableStyle([
        ('LEFTPADDING',  (0,0), (-1,-1), 4),
        ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING',   (0,0), (-1,-1), 4),
        ('BOTTOMPADDING',(0,0), (-1,-1), 4),
    ]))
    return t


def _asset_table(data_rows, styles, col_widths=None):
    """Styled data table with alternating rows."""
    if col_widths is None:
        col_widths = [5.5*cm, 2.5*cm, 2*cm, 2.5*cm, 2.5*cm]

    header = [Paragraph(h, styles['table_hdr']) for h in data_rows[0]]
    body   = []
    for row in data_rows[1:]:
        body.append([Paragraph(str(c), styles['table_cell']) if isinstance(c, str)
                     else c for c in row])

    t = Table([header] + body, colWidths=col_widths, repeatRows=1)

    ts = [
        ('BACKGROUND',    (0,0), (-1,0),  NAVY),
        ('TEXTCOLOR',     (0,0), (-1,0),  WHITE),
        ('FONTNAME',      (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',      (0,0), (-1,0),  8),
        ('TOPPADDING',    (0,0), (-1,0),  7),
        ('BOTTOMPADDING', (0,0), (-1,0),  7),
        ('LEFTPADDING',   (0,0), (-1,-1), 6),
        ('RIGHTPADDING',  (0,0), (-1,-1), 6),
        ('FONTSIZE',      (0,1), (-1,-1), 8),
        ('TOPPADDING',    (0,1), (-1,-1), 5),
        ('BOTTOMPADDING', (0,1), (-1,-1), 5),
        ('GRID',          (0,0), (-1,-1), 0.4, GREY_LINE),
        ('ROWBACKGROUNDS',(0,1), (-1,-1), [WHITE, GREY_BG]),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
    ]
    t.setStyle(TableStyle(ts))
    return t


# ── Main generator ───────────────────────────────────────────────────────────

class PDFReportGenerator:

    def generate(self, scan_results: list, cbom: dict) -> bytes:

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            leftMargin=1.8*cm,
            rightMargin=1.8*cm,
            topMargin=2.2*cm,
            bottomMargin=2.4*cm,
            title='Q-Shield Security Assessment Report',
            author='Q-Shield Scanner',
            subject='Quantum Cryptography Assessment',
        )

        S = _build_styles()
        story = []

        # ── Metrics ──────────────────────────────────────────────────────────
        total = len(scan_results)
        avg   = sum(r.get('quantum_score') or 0 for r in scan_results) / total if total else 0
        es    = min(1000, int(avg * 10))

        lc = {}
        for r in scan_results:
            lbl = r.get('label', 'Unknown')
            lc[lbl] = lc.get(lbl, 0) + 1

        n_vuln   = lc.get('Quantum Vulnerable', 0)
        n_pqc    = lc.get('PQC Ready', 0)
        n_secure = lc.get('Fully Quantum Safe', 0)

        # ── COVER PAGE ───────────────────────────────────────────────────────
        # Dark full-width background illusion via a table
        cover_bg = Table(
            [['']], colWidths=[doc.width], rowHeights=[doc.height * 0.42]
        )
        cover_bg.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), NAVY),
            ('TOPPADDING',    (0,0), (-1,-1), 0),
            ('BOTTOMPADDING', (0,0), (-1,-1), 0),
            ('LEFTPADDING',   (0,0), (-1,-1), 0),
            ('RIGHTPADDING',  (0,0), (-1,-1), 0),
        ]))

        # Build cover hero block inside the dark band
        def cover_hero():
            items = []
            items.append(Spacer(1, 1.2*cm))
            items.append(Paragraph('Q-SHIELD', S['cover_brand']))
            items.append(Paragraph('QUANTUM-PROOF SYSTEMS SCANNER', S['cover_sub']))
            items.append(HRFlowable(width='60%', thickness=1, color=GOLD, spaceAfter=10, spaceBefore=6))
            items.append(Paragraph('SECURITY ASSESSMENT REPORT', S['cover_report']))
            items.append(Spacer(1, 0.6*cm))
            # score
            score_col = _score_color(avg)
            score_hex = score_col.hexval() if hasattr(score_col, 'hexval') else '#FFFFFF'
            items.append(Paragraph(
                f'<font color="{score_hex}">{es}</font>',
                S['cover_score']
            ))
            items.append(Paragraph('ENTERPRISE SECURITY SCORE  /  1000', S['cover_slbl']))
            items.append(Spacer(1, 0.4*cm))
            items.append(Paragraph(
                f"Scan completed: {datetime.now(timezone.utc).strftime('%d %B %Y, %H:%M UTC')}",
                S['cover_date']
            ))
            items.append(Spacer(1, 0.8*cm))
            return items

        story += cover_hero()

        # Metric cards
        story.append(_cover_metric_table([
            ('VULNERABLE',   n_vuln,   RED),
            ('PQC READY',    n_pqc,    ORANGE),
            ('FULLY SECURE', n_secure, GREEN),
            ('TOTAL ASSETS', total,    BLUE_ACCENT),
        ], S))

        story.append(Spacer(1, 0.6*cm))

        # Risk gauge bar
        gauge_rows = []
        if total > 0:
            pct_vuln   = n_vuln / total
            pct_pqc    = n_pqc / total
            pct_secure = n_secure / total
            gauge_rows = [[
                Table([['']], colWidths=[doc.width * pct_vuln],   rowHeights=[0.35*cm],
                      style=TableStyle([('BACKGROUND',(0,0),(-1,-1),RED),   ('TOPPADDING',(0,0),(-1,-1),0), ('BOTTOMPADDING',(0,0),(-1,-1),0), ('LEFTPADDING',(0,0),(-1,-1),0), ('RIGHTPADDING',(0,0),(-1,-1),0)])),
                Table([['']], colWidths=[doc.width * pct_pqc],    rowHeights=[0.35*cm],
                      style=TableStyle([('BACKGROUND',(0,0),(-1,-1),ORANGE),('TOPPADDING',(0,0),(-1,-1),0), ('BOTTOMPADDING',(0,0),(-1,-1),0), ('LEFTPADDING',(0,0),(-1,-1),0), ('RIGHTPADDING',(0,0),(-1,-1),0)])),
                Table([['']], colWidths=[doc.width * pct_secure],  rowHeights=[0.35*cm],
                      style=TableStyle([('BACKGROUND',(0,0),(-1,-1),GREEN), ('TOPPADDING',(0,0),(-1,-1),0), ('BOTTOMPADDING',(0,0),(-1,-1),0), ('LEFTPADDING',(0,0),(-1,-1),0), ('RIGHTPADDING',(0,0),(-1,-1),0)])),
            ]]
            gauge = Table(gauge_rows, colWidths=[doc.width * pct_vuln, doc.width * pct_pqc, doc.width * pct_secure], hAlign='LEFT')
            gauge.setStyle(TableStyle([('TOPPADDING',(0,0),(-1,-1),0),('BOTTOMPADDING',(0,0),(-1,-1),0),('LEFTPADDING',(0,0),(-1,-1),0),('RIGHTPADDING',(0,0),(-1,-1),0)]))
            story.append(gauge)
            story.append(Paragraph(
                '<font color="#C0392B">■ Vulnerable</font>   '
                '<font color="#D35400">■ PQC Ready</font>   '
                '<font color="#1E8449">■ Fully Secure</font>',
                ParagraphStyle('legend', fontSize=7, alignment=TA_CENTER, leading=10, spaceAfter=2)
            ))

        story.append(RLPageBreak())

        # ── TABLE OF CONTENTS ────────────────────────────────────────────────
        story += _section_header('TABLE OF CONTENTS', S)
        toc_items = [
            ('1', 'Executive Summary',          '3'),
            ('2', 'Risk Assessment',            '4'),
            ('3', 'Asset Inventory',            '4'),
            ('4', 'Priority Remediation Plan',  '5'),
            ('5', 'PQC Migration Roadmap',      '5'),
        ]
        toc_data = [[
            Paragraph(no,    S['body']),
            Paragraph(title, S['body']),
            Paragraph(pg,    ParagraphStyle('toc_pg', fontSize=9, alignment=TA_RIGHT)),
        ] for no, title, pg in toc_items]

        toc_t = Table(toc_data, colWidths=[1*cm, doc.width - 2.5*cm, 1.5*cm])
        toc_t.setStyle(TableStyle([
            ('LINEBELOW',     (0,0), (-1,-1), 0.3, GREY_LINE),
            ('TOPPADDING',    (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING',   (0,0), (-1,-1), 0),
        ]))
        story.append(toc_t)
        story.append(RLPageBreak())

        # ── EXECUTIVE SUMMARY ────────────────────────────────────────────────
        story += _section_header('1.  EXECUTIVE SUMMARY', S)

        # key metrics row
        kpi_data = [[
            Paragraph(f'<b>{total}</b><br/><font size="7" color="#566573">Total Assets</font>', ParagraphStyle('kpi', fontSize=18, textColor=BLUE_ACCENT, fontName='Helvetica-Bold', alignment=TA_CENTER)),
            Paragraph(f'<b>{round(avg,1)}</b><br/><font size="7" color="#566573">Avg Score</font>',  ParagraphStyle('kpi', fontSize=18, textColor=_score_color(avg),  fontName='Helvetica-Bold', alignment=TA_CENTER)),
            Paragraph(f'<b>{es}/1000</b><br/><font size="7" color="#566573">Enterprise Score</font>', ParagraphStyle('kpi', fontSize=18, textColor=_score_color(avg),  fontName='Helvetica-Bold', alignment=TA_CENTER)),
            Paragraph(f'<b>{n_vuln}</b><br/><font size="7" color="#566573">Vulnerable</font>',       ParagraphStyle('kpi', fontSize=18, textColor=RED,               fontName='Helvetica-Bold', alignment=TA_CENTER)),
        ]]
        kpi_t = Table(kpi_data, colWidths=[doc.width/4]*4)
        kpi_t.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,-1), GREY_BG),
            ('BOX',           (0,0), (-1,-1), 0.5, GREY_LINE),
            ('INNERGRID',     (0,0), (-1,-1), 0.5, GREY_LINE),
            ('TOPPADDING',    (0,0), (-1,-1), 12),
            ('BOTTOMPADDING', (0,0), (-1,-1), 12),
            ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(kpi_t)
        story.append(Spacer(1, 0.5*cm))

        # CBOM summary
        cbom_summary = cbom.get('summary', {})
        if cbom_summary:
            story.append(Paragraph('Cryptographic Bill of Materials  (CBOM)  Summary', S['section_h2']))
            cbom_rows = [[Paragraph('Property', S['table_hdr']), Paragraph('Value', S['table_hdr'])]]
            for k, v in cbom_summary.items():
                cbom_rows.append([
                    Paragraph(str(k).replace('_', ' ').title(), S['table_cell']),
                    Paragraph(str(v), S['table_cell']),
                ])
            cbom_t = Table(cbom_rows, colWidths=[doc.width*0.55, doc.width*0.45])
            cbom_t.setStyle(TableStyle([
                ('BACKGROUND',    (0,0), (-1,0),  NAVY_LIGHT),
                ('TEXTCOLOR',     (0,0), (-1,0),  WHITE),
                ('FONTNAME',      (0,0), (-1,0),  'Helvetica-Bold'),
                ('ROWBACKGROUNDS',(0,1), (-1,-1), [WHITE, GREY_BG]),
                ('GRID',          (0,0), (-1,-1), 0.4, GREY_LINE),
                ('TOPPADDING',    (0,0), (-1,-1), 5),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                ('LEFTPADDING',   (0,0), (-1,-1), 6),
                ('RIGHTPADDING',  (0,0), (-1,-1), 6),
            ]))
            story.append(cbom_t)

        story.append(RLPageBreak())

        # ── RISK ASSESSMENT ──────────────────────────────────────────────────
        story += _section_header('2.  RISK ASSESSMENT', S)
        story.append(Paragraph('Top 5 Critical Risks', S['section_h2']))

        sorted_assets = sorted(scan_results, key=lambda x: x.get('quantum_score', 0))[:5]

        risk_rows = [['RANK', 'HOSTNAME', 'TLS', 'SCORE', 'RISK BAR', 'STATUS']]
        for i, r in enumerate(sorted_assets, 1):
            score = r.get('quantum_score', 0) or 0
            label = r.get('label', 'Unknown')
            sc    = _score_color(score)
            sc_hex = sc.hexval() if hasattr(sc, 'hexval') else '#888888'
            st_col = _status_color(label)
            st_hex = st_col.hexval() if hasattr(st_col, 'hexval') else '#888888'

            risk_rows.append([
                Paragraph(f'<b>#{i}</b>', ParagraphStyle('rank', fontSize=9, alignment=TA_CENTER, fontName='Helvetica-Bold')),
                Paragraph(r.get('hostname','—'), S['table_cell']),
                Paragraph(r.get('tls_version','—'), S['table_cell_c']),
                Paragraph(f'<font color="{sc_hex}"><b>{score}</b></font>', ParagraphStyle('sc', fontSize=9, alignment=TA_CENTER)),
                Paragraph(_score_bar_html(score), ParagraphStyle('bar', fontSize=9, fontName='Helvetica')),
                Paragraph(f'<font color="{st_hex}"><b>{_status_label(label)}</b></font>', ParagraphStyle('st', fontSize=8, alignment=TA_CENTER, fontName='Helvetica-Bold')),
            ])

        risk_t = Table(risk_rows, colWidths=[1.2*cm, 5.2*cm, 1.8*cm, 1.4*cm, 3.4*cm, 2.6*cm], repeatRows=1)
        risk_t.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,0),  NAVY),
            ('TEXTCOLOR',     (0,0), (-1,0),  WHITE),
            ('FONTNAME',      (0,0), (-1,0),  'Helvetica-Bold'),
            ('FONTSIZE',      (0,0), (-1,0),  8),
            ('ALIGN',         (0,0), (-1,-1), 'CENTER'),
            ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
            ('ROWBACKGROUNDS',(0,1), (-1,-1), [WHITE, GREY_BG]),
            ('GRID',          (0,0), (-1,-1), 0.4, GREY_LINE),
            ('TOPPADDING',    (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING',   (0,0), (-1,-1), 5),
            ('RIGHTPADDING',  (0,0), (-1,-1), 5),
        ]))
        story.append(risk_t)
        story.append(Spacer(1, 0.6*cm))

        # ── ASSET INVENTORY ──────────────────────────────────────────────────
        story += _section_header('3.  ASSET INVENTORY', S)

        def build_asset_group(title, items, tag_color):
            if not items:
                return
            story.append(KeepTogether([
                Paragraph(title, S['section_h2']),
            ]))
            rows = [['HOSTNAME', 'TLS VERSION', 'SCORE', 'RISK BAR', 'STATUS']]
            for r in items:
                score = r.get('quantum_score', 0) or 0
                label = r.get('label', 'Unknown')
                sc    = _score_color(score)
                sc_hex = sc.hexval() if hasattr(sc, 'hexval') else '#888888'
                st_col = _status_color(label)
                st_hex = st_col.hexval() if hasattr(st_col, 'hexval') else '#888888'
                rows.append([
                    Paragraph(r.get('hostname','—'), S['table_cell']),
                    Paragraph(r.get('tls_version','—'), S['table_cell_c']),
                    Paragraph(f'<font color="{sc_hex}"><b>{score}</b></font>', ParagraphStyle('sc2', fontSize=9, alignment=TA_CENTER)),
                    Paragraph(_score_bar_html(score), ParagraphStyle('bar2', fontSize=9, fontName='Helvetica')),
                    Paragraph(f'<font color="{st_hex}"><b>{_status_label(label)}</b></font>', ParagraphStyle('st2', fontSize=8, alignment=TA_CENTER, fontName='Helvetica-Bold')),
                ])
            t = Table(rows, colWidths=[5*cm, 2.2*cm, 1.8*cm, 3.4*cm, 3.2*cm], repeatRows=1)
            t.setStyle(TableStyle([
                ('BACKGROUND',    (0,0), (-1,0),  tag_color),
                ('TEXTCOLOR',     (0,0), (-1,0),  WHITE),
                ('FONTNAME',      (0,0), (-1,0),  'Helvetica-Bold'),
                ('FONTSIZE',      (0,0), (-1,0),  8),
                ('ALIGN',         (0,0), (-1,-1), 'CENTER'),
                ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
                ('ROWBACKGROUNDS',(0,1), (-1,-1), [WHITE, GREY_BG]),
                ('GRID',          (0,0), (-1,-1), 0.4, GREY_LINE),
                ('TOPPADDING',    (0,0), (-1,-1), 5),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                ('LEFTPADDING',   (0,0), (-1,-1), 5),
                ('RIGHTPADDING',  (0,0), (-1,-1), 5),
            ]))
            story.append(t)
            story.append(Spacer(1, 0.4*cm))

        build_asset_group(
            '⚠  Quantum Vulnerable Assets',
            [r for r in scan_results if r.get('label') == 'Quantum Vulnerable'],
            RED
        )
        build_asset_group(
            '◑  PQC Ready Assets',
            [r for r in scan_results if r.get('label') == 'PQC Ready'],
            ORANGE
        )
        build_asset_group(
            '✔  Fully Secure Assets',
            [r for r in scan_results if r.get('label') == 'Fully Quantum Safe'],
            GREEN
        )

        story.append(RLPageBreak())

        # ── REMEDIATION PLAN ─────────────────────────────────────────────────
        story += _section_header('4.  PRIORITY REMEDIATION ACTIONS', S)

        recs = []
        seen = set()
        for r in scan_results:
            for rec in (r.get('recommendations') or []):
                s = str(rec)
                if s not in seen:
                    seen.add(s)
                    recs.append(s)

        severity_cfg = [
            ('CRITICAL', RED,         RED_LIGHT),
            ('HIGH',     ORANGE,      ORANGE_LIGHT),
            ('MEDIUM',   GOLD,        colors.HexColor('#FEF9E7')),
            ('LOW',      BLUE_ACCENT, colors.HexColor('#D6EAF8')),
        ]

        rec_rows = []
        for i, rec in enumerate(recs[:10], 1):
            si   = min(i - 1, len(severity_cfg) - 1)
            sev, sev_col, sev_bg = severity_cfg[si]
            sev_hex = sev_col.hexval() if hasattr(sev_col, 'hexval') else '#888888'
            rec_rows.append([
                Table([[Paragraph(sev, ParagraphStyle('sev', fontSize=7, textColor=WHITE, fontName='Helvetica-Bold', alignment=TA_CENTER))]],
                      colWidths=[1.6*cm],
                      style=TableStyle([('BACKGROUND',(0,0),(-1,-1),sev_col),('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),('LEFTPADDING',(0,0),(-1,-1),2),('RIGHTPADDING',(0,0),(-1,-1),2)])),
                Paragraph(f'<b>{i}.</b>  {rec}', S['body']),
            ])

        if rec_rows:
            rec_t = Table(rec_rows, colWidths=[1.8*cm, doc.width - 1.8*cm])
            rec_t.setStyle(TableStyle([
                ('VALIGN',        (0,0), (-1,-1), 'TOP'),
                ('TOPPADDING',    (0,0), (-1,-1), 5),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                ('LINEBELOW',     (0,0), (-1,-1), 0.3, GREY_LINE),
                ('LEFTPADDING',   (0,0), (-1,-1), 0),
                ('RIGHTPADDING',  (0,0), (-1,-1), 0),
            ]))
            story.append(rec_t)

        story.append(Spacer(1, 0.6*cm))

        # ── PQC ROADMAP ──────────────────────────────────────────────────────
        story += _section_header('5.  PQC MIGRATION ROADMAP', S)

        roadmap = [
            ('1', 'Assess cryptographic assets',   'Immediate',    '0–2 weeks',   RED),
            ('2', 'Plan migration strategy',        'Short-term',   '1–2 months',  ORANGE),
            ('3', 'Pilot hybrid TLS deployment',    'Mid-term',     '2–4 months',  GOLD),
            ('4', 'Full PQC migration',             'Long-term',    '4–12 months', BLUE_ACCENT),
            ('5', 'Continuous monitoring & review', 'Ongoing',      'Perpetual',   GREEN),
        ]

        rm_hdr = [
            Paragraph('PHASE',    S['table_hdr']),
            Paragraph('ACTION',   S['table_hdr']),
            Paragraph('PRIORITY', S['table_hdr']),
            Paragraph('TIMELINE', S['table_hdr']),
        ]
        rm_rows = [rm_hdr]
        for ph, action, prio, time, col in roadmap:
            col_hex = col.hexval() if hasattr(col, 'hexval') else '#888888'
            rm_rows.append([
                Table([[Paragraph(ph, ParagraphStyle('ph', fontSize=11, textColor=WHITE, fontName='Helvetica-Bold', alignment=TA_CENTER))]],
                      colWidths=[1*cm],
                      style=TableStyle([('BACKGROUND',(0,0),(-1,-1),col),('TOPPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),6),('LEFTPADDING',(0,0),(-1,-1),2),('RIGHTPADDING',(0,0),(-1,-1),2),('ROUNDEDCORNERS',[4,4,4,4])])),
                Paragraph(action, S['table_cell']),
                Paragraph(f'<font color="{col_hex}"><b>{prio}</b></font>', ParagraphStyle('prio', fontSize=8, alignment=TA_CENTER)),
                Paragraph(time,   S['table_cell_c']),
            ])

        rm_t = Table(rm_rows, colWidths=[1.5*cm, 7.5*cm, 2.5*cm, 2.5*cm], repeatRows=1)
        rm_t.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,0),  NAVY),
            ('TEXTCOLOR',     (0,0), (-1,0),  WHITE),
            ('FONTNAME',      (0,0), (-1,0),  'Helvetica-Bold'),
            ('FONTSIZE',      (0,0), (-1,0),  8),
            ('ALIGN',         (0,0), (-1,-1), 'CENTER'),
            ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
            ('ROWBACKGROUNDS',(0,1), (-1,-1), [WHITE, GREY_BG]),
            ('GRID',          (0,0), (-1,-1), 0.4, GREY_LINE),
            ('TOPPADDING',    (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING',   (0,0), (-1,-1), 6),
            ('RIGHTPADDING',  (0,0), (-1,-1), 6),
        ]))
        story.append(rm_t)
        story.append(Spacer(1, 0.8*cm))

        # disclaimer
        story.append(HRFlowable(width='100%', thickness=0.5, color=GREY_LINE, spaceBefore=4, spaceAfter=4))
        story.append(Paragraph(
            'This report is generated automatically by Q-Shield and is intended for internal security assessment purposes only. '
            'All data reflects the state of scanned assets at the time of scan. Handle as CONFIDENTIAL.',
            S['body_sm']
        ))

        doc.build(story, canvasmaker=NumberedCanvas)
        return buf.getvalue()


# ── Demo runner ──────────────────────────────────────────────────────────────
if __name__ == '__main__':
    SAMPLE_RESULTS = [
        {'hostname': 'portal.pnb.co.in',      'tls_version': 'TLSv1.2', 'quantum_score': 31.5, 'label': 'Quantum Vulnerable',  'recommendations': ['Enable ECDHE as the only key exchange method. This provides forward secrecy.', 'Configure cipher suite priority: TLS_AES_256_GCM_SHA384 first, TLS_CHACHA20_POLY1305_SHA256 second. Remove CBC and RC4 suites.', 'Certificate expires in 22 days. Renew now to avoid service disruption. Set up auto-renewal (Lets Encrypt / ACME).']},
        {'hostname': 'api.pnb.co.in',         'tls_version': 'TLSv1.2', 'quantum_score': 59.0, 'label': 'Quantum Vulnerable',  'recommendations': ['Phase 2 (PQC Migration): Implement ML-KEM-768 (Kyber) [FIPS 203] for post-quantum key encapsulation alongside ECDHE (hybrid approach).', 'Certificate expires in 62 days. Renew now to avoid service disruption.']},
        {'hostname': 'rbi.org.in',             'tls_version': 'TLSv1.2', 'quantum_score': 61.5, 'label': 'PQC Ready',           'recommendations': ['Certificate expires in 88 days. Renew now to avoid service disruption.']},
        {'hostname': 'www.pnbindia.in',        'tls_version': 'TLSv1.2', 'quantum_score': 69.5, 'label': 'PQC Ready',           'recommendations': ['Certificate expires in 72 days. Renew now to avoid service disruption.']},
        {'hostname': 'icicibank.com',          'tls_version': 'TLSv1.2', 'quantum_score': 69.5, 'label': 'PQC Ready',           'recommendations': ['Upgrade certificate key size to minimum 3072-bit RSA (current: 256-bit).', 'Certificate expires in 65 days.']},
        {'hostname': 'pnb.co.in',             'tls_version': 'TLSv1.2', 'quantum_score': 71.5, 'label': 'PQC Ready',           'recommendations': ['Certificate expires in 70 days.']},
        {'hostname': 'google.com',             'tls_version': 'TLSv1.3', 'quantum_score': 75.5, 'label': 'PQC Ready',           'recommendations': []},
        {'hostname': 'neverssl.com',           'tls_version': 'TLSv1.3', 'quantum_score': 84.5, 'label': 'PQC Ready',           'recommendations': []},
        {'hostname': 'cloudflare.com',         'tls_version': 'TLSv1.3', 'quantum_score': 78.0, 'label': 'PQC Ready',           'recommendations': []},
        {'hostname': 'github.com',             'tls_version': 'TLSv1.3', 'quantum_score': 78.0, 'label': 'PQC Ready',           'recommendations': []},
        {'hostname': 'yahoo.com',              'tls_version': 'TLSv1.3', 'quantum_score': 77.5, 'label': 'PQC Ready',           'recommendations': []},
        {'hostname': 'hdfcbank.com',           'tls_version': 'TLSv1.3', 'quantum_score': 88.0, 'label': 'PQC Ready',           'recommendations': []},
        {'hostname': 'netbanking.pnb.co.in',   'tls_version': 'TLSv1.3', 'quantum_score': 84.5, 'label': 'PQC Ready',           'recommendations': []},
        {'hostname': 'sbi.co.in',             'tls_version': 'TLSv1.3', 'quantum_score': 90.0, 'label': 'Fully Quantum Safe',  'recommendations': []},
        {'hostname': 'quantum.pnb.co.in',     'tls_version': 'TLSv1.3', 'quantum_score': 98.0, 'label': 'Fully Quantum Safe',  'recommendations': []},
    ]

    SAMPLE_CBOM = {
        'summary': {
            'total_assets':        15,
            'total_certs':         15,
            'total_keys':           5,
            'total_algs':           5,
            'total_protocols':      7,
            'pqc_count':            1,
            'quantum_vulnerable':  15,
            'most_used_algorithm': 'RSA-SHA256',
            'reused_certificates':  0,
        }
    }

    gen = PDFReportGenerator()
    pdf_bytes = gen.generate(SAMPLE_RESULTS, SAMPLE_CBOM)

    out_path = '/mnt/user-data/outputs/qshield_report_enhanced.pdf'
    with open(out_path, 'wb') as f:
        f.write(pdf_bytes)

    print(f'Report written → {out_path}  ({len(pdf_bytes):,} bytes)')
