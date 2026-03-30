# backend/reporting/pdf_report.py
from reportlab.lib                 import colors
from reportlab.lib.pagesizes       import A4
from reportlab.lib.styles          import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units           import cm
from reportlab.platypus            import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
from reportlab.platypus            import PageBreak as RLPageBreak
from reportlab.lib.enums           import TA_CENTER, TA_LEFT
from datetime                      import datetime, timezone
import io, logging

logger = logging.getLogger(__name__)

NAVY  = colors.HexColor('#1B2A4A')
GOLD  = colors.HexColor('#D4AC0D')
RED   = colors.HexColor('#8B1A1A')
GREEN = colors.HexColor('#27AE60')
ORANGE= colors.HexColor('#F39C12')
CRIMSON=colors.HexColor('#E74C3C')
WHITE = colors.white

LABEL_COLORS = {
    'Fully Quantum Safe': GREEN,
    'PQC Ready':          ORANGE,
    'Quantum Vulnerable': RED,
    'Critical':           NAVY,
}

class PDFReportGenerator:
    def generate(self, scan_results: list, cbom: dict) -> bytes:
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4,
                                leftMargin=1.8*cm, rightMargin=1.8*cm,
                                topMargin=2*cm, bottomMargin=2*cm)
        styles  = getSampleStyleSheet()
        story   = []
        total   = len(scan_results)
        avg_sc  = sum(r.get('quantum_score') or 0 for r in scan_results) / total if total else 0
        es      = min(1000, int(avg_sc * 10))
        tier    = 'Elite-PQC' if es > 700 else 'Standard' if es >= 400 else 'Legacy'
        lc      = {}
        for r in scan_results:
            lbl = r.get('label', 'Unknown')
            lc[lbl] = lc.get(lbl, 0) + 1

        # ── Cover Page ──
        story.append(Spacer(1, 2*cm))
        story.append(Paragraph('Q-SHIELD', ParagraphStyle('Cover', fontName='Helvetica-Bold',
            fontSize=36, textColor=GOLD, alignment=TA_CENTER)))
        story.append(Paragraph('Quantum-Proof Systems Scanner', ParagraphStyle('Sub', fontName='Helvetica',
            fontSize=14, textColor=NAVY, alignment=TA_CENTER)))
        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width='80%', color=GOLD, thickness=2))
        story.append(Spacer(1, 0.4*cm))
        story.append(Paragraph('Cryptographic Risk Assessment Report', ParagraphStyle('Title2',
            fontName='Helvetica-Bold', fontSize=18, textColor=NAVY, alignment=TA_CENTER)))
        story.append(Paragraph('PNB Cybersecurity Hackathon 2026 — Garuda Grid, TIET',
            ParagraphStyle('Auth', fontName='Helvetica', fontSize=10, textColor=colors.grey, alignment=TA_CENTER)))
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph(f'Generated: {datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")}',
            ParagraphStyle('Date', fontName='Helvetica', fontSize=9, textColor=colors.grey, alignment=TA_CENTER)))
        story.append(Spacer(1, 1.5*cm))

        # Executive Summary table
        summary_data = [
            ['Total Assets Scanned', str(total)],
            ['Average Quantum Score', f'{round(avg_sc, 1)} / 100'],
            ['Enterprise Cyber Score', f'{es} / 1000  ({tier})'],
            ['Fully Quantum Safe', str(lc.get('Fully Quantum Safe', 0))],
            ['PQC Ready', str(lc.get('PQC Ready', 0))],
            ['Quantum Vulnerable', str(lc.get('Quantum Vulnerable', 0))],
            ['Critical', str(lc.get('Critical', 0))],
        ]
        t = Table(summary_data, colWidths=[9*cm, 6*cm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#EBF5FB')),
            ('FONTNAME',   (0,0), (-1,-1), 'Helvetica'),
            ('FONTSIZE',   (0,0), (-1,-1), 10),
            ('FONTNAME',   (0,0), (0,-1), 'Helvetica-Bold'),
            ('GRID',       (0,0), (-1,-1), 0.5, colors.HexColor('#CCCCCC')),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING',(0,0),(-1,-1), 6),
        ]))
        story.append(t)
        story.append(RLPageBreak())

        # ── Asset Detail Table ──
        story.append(Paragraph('Asset-by-Asset Quantum Risk Assessment',
            ParagraphStyle('H1', fontName='Helvetica-Bold', fontSize=14, textColor=NAVY)))
        story.append(Spacer(1, 0.3*cm))

        detail_hdr = [['Asset / Hostname', 'TLS', 'Key Size', 'Score', 'Label', 'HNDL Risk', 'Cert Days']]
        detail_rows = []
        for r in scan_results:
            sc      = r.get('quantum_score') or 0
            label   = r.get('label', '--')
            lcolor  = LABEL_COLORS.get(label, NAVY)
            days    = r.get('cert_days_remaining', 0)
            days_str= str(days) if days else '--'
            detail_rows.append([
                r.get('hostname', '--')[:35],
                r.get('tls_version', '--'),
                f"{r.get('cert_key_size','--')}-bit",
                f'{sc}/100',
                Paragraph(f'<font color="#{lcolor.hexval()[1:][:6]}">{label}</font>',
                          ParagraphStyle('lbl', fontName='Helvetica-Bold', fontSize=8)),
                r.get('hndl_risk', '--'),
                days_str,
            ])
        detail_tbl = Table(detail_hdr + detail_rows,
            colWidths=[5.5*cm,1.8*cm,1.6*cm,1.6*cm,3.2*cm,2.0*cm,1.8*cm])
        detail_tbl.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,0), NAVY),
            ('TEXTCOLOR',     (0,0),(-1,0), WHITE),
            ('FONTNAME',      (0,0),(-1,0), 'Helvetica-Bold'),
            ('FONTSIZE',      (0,0),(-1,-1), 8),
            ('GRID',          (0,0),(-1,-1), 0.4, colors.HexColor('#CCCCCC')),
            ('ROWBACKGROUNDS',(0,1),(-1,-1), [WHITE, colors.HexColor('#FFF9E6')]),
            ('TOPPADDING',    (0,0),(-1,-1), 4),
            ('BOTTOMPADDING', (0,0),(-1,-1), 4),
        ]))
        story.append(detail_tbl)
        story.append(Spacer(1, 0.5*cm))

        # ── Recommendations Section ──
        story.append(RLPageBreak())
        story.append(Paragraph('PQC Migration Recommendations',
            ParagraphStyle('H1', fontName='Helvetica-Bold', fontSize=14, textColor=NAVY)))
        story.append(Spacer(1, 0.3*cm))
        all_recs = set()
        for r in scan_results:
            for rec in (r.get('recommendations') or []):
                all_recs.add(str(rec))
        for i, rec in enumerate(list(all_recs)[:12], 1):
            story.append(Paragraph(f'{i}. {rec}',
                ParagraphStyle('Rec', fontName='Helvetica', fontSize=9,
                               leftIndent=0.3*cm, spaceBefore=4)))

    

        story.append(RLPageBreak())
        story.append(Paragraph('Cryptographic Bill of Materials (CBOM) Summary',
            ParagraphStyle('H1', fontName='Helvetica-Bold', fontSize=14, textColor=NAVY)))
        story.append(Spacer(1, 0.3*cm))

        summary = cbom.get('summary', {})

        cbom_table_data = [
            ['Total Certificates', str(summary.get('total_certs', '--'))],
            ['Total Algorithms', str(summary.get('total_algs', '--'))],
            ['PQC Enabled Systems', str(summary.get('pqc_count', '--'))],
            ['Quantum Vulnerable Systems', str(summary.get('quantum_vulnerable', '--'))],
            ['Most Used Algorithm', str(summary.get('most_used_algorithm', '--'))],
            ['Reused Certificates', str(summary.get('reused_certificates', '--'))],
        ]

        cbom_table = Table(cbom_table_data, colWidths=[8*cm, 7*cm])
        cbom_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#E8F8F5')),
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('GRID', (0,0), (-1,-1), 0.4, colors.HexColor('#CCCCCC')),
        ]))
        story.append(cbom_table)
        story.append(Spacer(1, 0.5*cm))

        reuse = cbom.get('certificate_reuse', {})
        if reuse:
            story.append(Paragraph('Certificate Reuse Risk Analysis',
                ParagraphStyle('H2', fontName='Helvetica-Bold', fontSize=12, textColor=CRIMSON)))
            story.append(Spacer(1, 0.2*cm))
            for cert, hosts in reuse.items():
                story.append(Paragraph(
                    f'Certificate <b>{cert[:12]}...</b> is reused across <b>{len(hosts)}</b> assets.',
                    ParagraphStyle('Reuse', fontName='Helvetica', fontSize=9)
                ))

        algo_usage = cbom.get('algorithm_usage', {})
        if algo_usage:
            story.append(Paragraph('Algorithm Risk Distribution',
                ParagraphStyle('H2', fontName='Helvetica-Bold', fontSize=12, textColor=NAVY)))
            story.append(Spacer(1, 0.2*cm))
            for alg, count in sorted(algo_usage.items(), key=lambda x: x[1], reverse=True)[:6]:
                story.append(Paragraph(f'{alg} → used in {count} assets',
                    ParagraphStyle('Alg', fontName='Helvetica', fontSize=9)))

        risk_summary = cbom.get('risk_summary', {})
        if risk_summary:
            story.append(Paragraph('System-Level Risk Summary',
                ParagraphStyle('H2', fontName='Helvetica-Bold', fontSize=12, textColor=CRIMSON)))
            story.append(Paragraph(f"Quantum Vulnerable Assets: {risk_summary.get('quantum_vulnerable_assets', 0)}", styles['Normal']))
            story.append(Paragraph(f"Weak Cipher Usage: {risk_summary.get('weak_cipher_assets', 0)}", styles['Normal']))
            story.append(Paragraph(f"No Forward Secrecy: {risk_summary.get('no_forward_secrecy', 0)}", styles['Normal']))

        doc.build(story)
        return buf.getvalue()