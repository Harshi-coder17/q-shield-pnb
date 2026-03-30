# backend/reporting/pdf_report.py

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
from reportlab.platypus import PageBreak as RLPageBreak
from reportlab.lib.enums import TA_CENTER
from datetime import datetime, timezone
import io, logging

logger = logging.getLogger(__name__)

NAVY   = colors.HexColor('#1B2A4A')
GOLD   = colors.HexColor('#D4AC0D')
RED    = colors.HexColor('#E74C3C')
GREEN  = colors.HexColor('#27AE60')
ORANGE = colors.HexColor('#F39C12')
WHITE  = colors.white

LABEL_COLORS = {
    'Fully Quantum Safe': GREEN,
    'PQC Ready': ORANGE,
    'Quantum Vulnerable': RED,
    'Critical': RED,
}

LABEL_BG = {
    'Fully Quantum Safe': colors.HexColor('#E8F8F5'),
    'PQC Ready': colors.HexColor('#FEF9E7'),
    'Quantum Vulnerable': colors.HexColor('#FDEDEC'),
    'Critical': colors.HexColor('#FDEDEC'),
}

class PDFReportGenerator:

    def _score_bar(self, score):
        filled = int(score / 10)
        return '█' * filled + '░' * (10 - filled)

    def generate(self, scan_results: list, cbom: dict) -> bytes:
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4,
                                leftMargin=1.8*cm, rightMargin=1.8*cm,
                                topMargin=2*cm, bottomMargin=2*cm)

        styles = getSampleStyleSheet()
        story = []

        total = len(scan_results)
        avg = sum(r.get('quantum_score') or 0 for r in scan_results) / total if total else 0
        es = min(1000, int(avg * 10))

        lc = {}
        for r in scan_results:
            lbl = r.get('label', 'Unknown')
            lc[lbl] = lc.get(lbl, 0) + 1

        # ───────── COVER ─────────
        story.append(Spacer(1, 2*cm))
        story.append(Paragraph("Q-SHIELD", ParagraphStyle('c1',
            fontName='Helvetica-Bold', fontSize=36, textColor=GOLD, alignment=TA_CENTER)))

        story.append(Paragraph("Quantum-Proof Systems Scanner",
            ParagraphStyle('c2', fontSize=14, textColor=NAVY, alignment=TA_CENTER)))

        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width='80%', color=GOLD, thickness=2))
        story.append(Spacer(1, 0.5*cm))

        story.append(Paragraph(
            f"Generated: {datetime.now(timezone.utc).strftime('%d %B %Y, %H:%M UTC')}",
            ParagraphStyle('c3', fontSize=9, alignment=TA_CENTER)
        ))

        story.append(Spacer(1, 1*cm))

        # ───────── RISK BANNER ─────────
        story.append(Paragraph(
            f"🔴 {lc.get('Quantum Vulnerable',0)} Vulnerable &nbsp;&nbsp; "
            f"🟡 {lc.get('PQC Ready',0)} PQC Ready &nbsp;&nbsp; "
            f"🟢 {lc.get('Fully Quantum Safe',0)} Secure",
            ParagraphStyle('banner', fontSize=14, alignment=TA_CENTER)
        ))

        story.append(Spacer(1, 0.5*cm))

        # ───────── SCORE ─────────
        story.append(Paragraph(
            f"<b>Enterprise Score:</b> {es}/1000<br/>"
            f"<b>Visual:</b> {self._score_bar(avg)} ({round(avg,1)}%)",
            styles['Normal']
        ))

        story.append(Spacer(1, 1*cm))

        # ───────── SUMMARY TABLE ─────────
        summary = [
            ['Total Assets', total],
            ['Avg Score', f'{round(avg,1)}/100'],
            ['Enterprise Score', es],
        ]

        t = Table(summary, colWidths=[7*cm, 7*cm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#EBF5FB')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey)
        ]))
        story.append(t)

        story.append(RLPageBreak())

        # ───────── TOP RISKS ─────────
        story.append(Paragraph("🔥 TOP CRITICAL RISKS",
            ParagraphStyle('h1', fontSize=14, textColor=RED)))

        sorted_assets = sorted(scan_results, key=lambda x: x.get('quantum_score', 0))[:5]

        for i, r in enumerate(sorted_assets, 1):
            story.append(Paragraph(
                f"{i}. {r.get('hostname')} → Score {r.get('quantum_score')}",
                styles['Normal']
            ))

        story.append(Spacer(1, 0.5*cm))

        # ───────── GROUPED TABLE ─────────
        def build_table(title, items):
            if not items: return

            story.append(Paragraph(title,
                ParagraphStyle('grp', fontSize=13, textColor=NAVY)))

            data = [['Host','TLS','Score','Label']]

            for r in items:
                lbl = r.get('label')
                data.append([
                    r.get('hostname'),
                    r.get('tls_version'),
                    r.get('quantum_score'),
                    Paragraph(f'<b>{lbl}</b>', styles['Normal'])
                ])

            tbl = Table(data)
            style = [
                ('BACKGROUND',(0,0),(-1,0),NAVY),
                ('TEXTCOLOR',(0,0),(-1,0),WHITE),
                ('GRID',(0,0),(-1,-1),0.3,colors.grey)
            ]

            for i, r in enumerate(items, start=1):
                style.append(('BACKGROUND',(0,i),(-1,i), LABEL_BG.get(r.get('label'), WHITE)))

            tbl.setStyle(TableStyle(style))
            story.append(tbl)
            story.append(Spacer(1,0.4*cm))

        build_table("🔴 Quantum Vulnerable",
                    [r for r in scan_results if r.get('label')=='Quantum Vulnerable'])

        build_table("🟡 PQC Ready",
                    [r for r in scan_results if r.get('label')=='PQC Ready'])

        build_table("🟢 Fully Secure",
                    [r for r in scan_results if r.get('label')=='Fully Quantum Safe'])

        story.append(RLPageBreak())

        # ───────── RECOMMENDATIONS ─────────
        story.append(Paragraph("🔧 PRIORITY ACTIONS",
            ParagraphStyle('h2', fontSize=14, textColor=NAVY)))

        recs = set()
        for r in scan_results:
            for rec in (r.get('recommendations') or []):
                recs.add(str(rec))

        for i, rec in enumerate(list(recs)[:10],1):
            story.append(Paragraph(f"{i}. {rec}", styles['Normal']))

        story.append(RLPageBreak())

        # ───────── CBOM INSIGHTS ─────────
        story.append(Paragraph("📊 CBOM INSIGHTS",
            ParagraphStyle('h3', fontSize=14, textColor=NAVY)))

        summary = cbom.get('summary', {})
        vuln = summary.get('quantum_vulnerable',0)
        total_c = summary.get('total_certs',1)

        percent = int((vuln/total_c)*100) if total_c else 0

        story.append(Paragraph(
            f"⚠ {percent}% systems are quantum vulnerable",
            styles['Normal']
        ))

        for k,v in summary.items():
            story.append(Paragraph(f"{k}: {v}", styles['Normal']))

        doc.build(story)
        return buf.getvalue()