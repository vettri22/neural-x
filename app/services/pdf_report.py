"""
PDF Security Report Generator
Generates branded NEURAL-X PDF reports using ReportLab.
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                          'app', 'static', 'reports')


def _ensure_dir():
    os.makedirs(REPORT_DIR, exist_ok=True)


def _risk_color_rgb(category: str):
    colors = {
        'Safe': (0, 200, 100),
        'Suspicious': (255, 170, 0),
        'High Risk': (255, 100, 0),
        'Critical Threat': (220, 0, 50),
    }
    r, g, b = colors.get(category, (128, 128, 128))
    return r / 255, g / 255, b / 255


def generate_pdf_report(scan_data: Dict[str, Any]) -> Optional[str]:
    """
    Generate a PDF security report.
    Returns the relative path to the generated PDF, or None on failure.
    """
    _ensure_dir()

    scan_id = scan_data.get('id', 'unknown')
    filename = f'neural-x-report-{scan_id}-{datetime.utcnow().strftime("%Y%m%d%H%M%S")}.pdf'
    filepath = os.path.join(REPORT_DIR, filename)
    relative_path = f'reports/{filename}'

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable, Image as RLImage)
        from reportlab.lib.enums import TA_CENTER, TA_LEFT

        doc = SimpleDocTemplate(filepath, pagesize=A4,
                                rightMargin=2*cm, leftMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)
        story = []
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle('NXTitle', fontSize=22, textColor=colors.HexColor('#00ff88'),
                                     alignment=TA_CENTER, spaceAfter=6, fontName='Helvetica-Bold')
        subtitle_style = ParagraphStyle('NXSub', fontSize=10, textColor=colors.HexColor('#888888'),
                                        alignment=TA_CENTER, spaceAfter=20)
        heading_style = ParagraphStyle('NXHeading', fontSize=13, textColor=colors.HexColor('#00ccff'),
                                       spaceBefore=16, spaceAfter=6, fontName='Helvetica-Bold')
        body_style = ParagraphStyle('NXBody', fontSize=9, textColor=colors.HexColor('#333333'),
                                    spaceAfter=4, leading=14)
        risk_style = ParagraphStyle('NXRisk', fontSize=16, alignment=TA_CENTER,
                                    spaceBefore=8, spaceAfter=8, fontName='Helvetica-Bold')

        # ---- Header ----
        story.append(Paragraph('NEURAL-X', title_style))
        story.append(Paragraph('AI Cyber Defense Platform — Security Report', subtitle_style))
        story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#00ff88')))
        story.append(Spacer(1, 0.4*cm))

        # ---- Scan Info ----
        story.append(Paragraph('Scan Information', heading_style))
        scan_date = scan_data.get('scan_date', datetime.utcnow().isoformat())
        url = scan_data.get('url', 'N/A')
        domain = scan_data.get('domain', 'N/A')
        category = scan_data.get('risk_category', 'Unknown')
        score = scan_data.get('threat_score', 0)

        info_data = [
            ['Scan Timestamp:', str(scan_date)],
            ['Target URL:', str(url)[:80]],
            ['Domain:', str(domain)],
            ['Scan Type:', str(scan_data.get('scan_type', 'url')).upper()],
        ]
        info_table = Table(info_data, colWidths=[4*cm, 13*cm])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#00ccff')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(info_table)

        # ---- Threat Score ----
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph('Threat Assessment', heading_style))
        r, g, b = _risk_color_rgb(category)
        risk_color = colors.Color(r, g, b)

        score_style = ParagraphStyle('Score', fontSize=36, alignment=TA_CENTER,
                                     spaceBefore=4, spaceAfter=4, fontName='Helvetica-Bold',
                                     textColor=risk_color)
        story.append(Paragraph(f'{score}/100', score_style))

        risk_p = ParagraphStyle('RiskCat', fontSize=18, alignment=TA_CENTER,
                                textColor=risk_color, spaceAfter=12, fontName='Helvetica-Bold')
        story.append(Paragraph(f'⬛ {category}', risk_p))

        # ---- Risk Factors ----
        risk_factors = scan_data.get('risk_factors', [])
        if risk_factors:
            story.append(Paragraph('Risk Factors Detected', heading_style))
            for factor in risk_factors:
                story.append(Paragraph(f'• {factor}', body_style))

        # ---- Recommendations ----
        recs = scan_data.get('recommendations', [])
        if recs:
            story.append(Paragraph('Security Recommendations', heading_style))
            for rec in recs:
                story.append(Paragraph(f'✓ {rec}', body_style))

        # ---- Domain Info ----
        domain_info = scan_data.get('domain_info', {})
        if domain_info:
            story.append(Paragraph('Domain Intelligence', heading_style))
            whois = domain_info.get('whois', {})
            d_data = [
                ['Registrar:', str(whois.get('registrar', 'N/A'))],
                ['Domain Age:', f'{domain_info.get("domain_age_days", "N/A")} days'],
                ['SSL Valid:', 'Yes' if domain_info.get('ssl', {}).get('valid') else 'No'],
                ['Country:', str(whois.get('registrant_country', 'N/A'))],
            ]
            d_table = Table(d_data, colWidths=[4*cm, 13*cm])
            d_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#00ccff')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(d_table)

        # ---- QR Content ----
        qr_content = scan_data.get('qr_content')
        if qr_content:
            story.append(Paragraph('QR Code Content', heading_style))
            story.append(Paragraph(str(qr_content)[:500], body_style))

        # ---- Screenshot ----
        screenshot = scan_data.get('screenshot_path')
        if screenshot:
            story.append(Paragraph('Website Preview', heading_style))
            full_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                'app', 'static', screenshot
            )
            if os.path.exists(full_path):
                try:
                    story.append(RLImage(full_path, width=15*cm, height=8.4*cm))
                except Exception:
                    story.append(Paragraph('Screenshot not renderable', body_style))

        # ---- Footer ----
        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width='100%', thickness=0.5, color=colors.HexColor('#444444')))
        footer_style = ParagraphStyle('Footer', fontSize=7, textColor=colors.HexColor('#888888'),
                                      alignment=TA_CENTER, spaceBefore=4)
        story.append(Paragraph(
            f'Generated by NEURAL-X AI Cyber Defense Platform | {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC | '
            'This report is for informational purposes only.',
            footer_style
        ))

        doc.build(story)
        logger.info(f'PDF report generated: {filepath}')
        return relative_path

    except ImportError:
        logger.warning('reportlab not installed — PDF generation unavailable')
        return None
    except Exception as e:
        logger.error(f'PDF generation failed: {e}')
        return None
