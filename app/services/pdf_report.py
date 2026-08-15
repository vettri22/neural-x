"""
PDF Security Report Generator — v2
Generates branded NEURAL-X reports using ReportLab.
v2 adds: Journal authenticity section, hybrid scores, API check summary.
All v1 scan types (url/qr/image) preserved unchanged.
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
    colors_map = {
        'Safe':           (0,   200, 100),
        'Suspicious':     (255, 170,   0),
        'High Risk':      (255, 100,   0),
        'Critical Threat':(220,   0,  50),
    }
    r, g, b = colors_map.get(category, (128, 128, 128))
    return r / 255, g / 255, b / 255


def generate_pdf_report(scan_data: Dict[str, Any]) -> Optional[str]:
    """
    Generate PDF security report.
    Returns relative path 'reports/<filename>' or None on failure.
    scan_data may include v2 keys: journal_score, hybrid_score, phishing_prob, journal_data.
    """
    _ensure_dir()

    scan_id  = scan_data.get('id', 'unknown')
    filename = f'neural-x-report-{scan_id}-{datetime.utcnow().strftime("%Y%m%d%H%M%S")}.pdf'
    filepath = os.path.join(REPORT_DIR, filename)
    relative = f'reports/{filename}'

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable,
                                        Image as RLImage, KeepTogether)
        from reportlab.lib.enums import TA_CENTER, TA_LEFT

        doc   = SimpleDocTemplate(filepath, pagesize=A4,
                                  rightMargin=2*cm, leftMargin=2*cm,
                                  topMargin=2*cm, bottomMargin=2*cm)
        story = []

        def _add_page_number(canvas, doc_):
            canvas.saveState()
            canvas.setFont('Helvetica', 7)
            canvas.setFillColor(colors.HexColor('#5a6b78'))
            canvas.drawCentredString(A4[0] / 2.0, 1.2*cm, f'Page {doc_.page}')
            canvas.drawString(2*cm, 1.2*cm,
                              f'Generated {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}')
            canvas.drawRightString(A4[0] - 2*cm, 1.2*cm, 'NEURAL-X — Confidential Scan Report')
            canvas.restoreState()

        # ── Styles ──────────────────────────────────────────────────────────
        # IMPORTANT: every style below sets `leading` explicitly (~1.3x the
        # font size). ReportLab's ParagraphStyle defaults `leading` to a flat
        # 12pt regardless of fontSize when it isn't given — for the 24pt
        # title and 34pt score styles that squashed the line box far shorter
        # than the glyphs themselves, so the next paragraph started before
        # the tall text had finished, rendering as overlapping text
        # ("NEURAL-X" over the subtitle, the score over the risk-level
        # badge). Explicit leading fixes this for every font size used here.
        title_s    = ParagraphStyle('NXTitle',   fontSize=24, leading=30, textColor=colors.HexColor('#00ff88'),
                                    alignment=TA_CENTER, spaceAfter=6, fontName='Helvetica-Bold')
        sub_s      = ParagraphStyle('NXSub',     fontSize=9,  leading=13, textColor=colors.HexColor('#5a6b78'),
                                    alignment=TA_CENTER, spaceAfter=16)
        heading_s  = ParagraphStyle('NXHeading', fontSize=12, leading=15, textColor=colors.HexColor('#00ccff'),
                                    spaceBefore=14, spaceAfter=5, fontName='Helvetica-Bold')
        purple_h   = ParagraphStyle('NXPurple',  fontSize=12, leading=15, textColor=colors.HexColor('#bf60ff'),
                                    spaceBefore=14, spaceAfter=5, fontName='Helvetica-Bold')
        body_s     = ParagraphStyle('NXBody',    fontSize=9,  textColor=colors.HexColor('#333333'),
                                    spaceAfter=3, leading=13)
        center_s   = ParagraphStyle('NXCenter',  fontSize=9,  leading=13, textColor=colors.HexColor('#555555'),
                                    alignment=TA_CENTER)
        footer_s   = ParagraphStyle('NXFooter',  fontSize=7,  leading=10, textColor=colors.HexColor('#5a6b78'),
                                    alignment=TA_CENTER, spaceBefore=4)
        # break-anywhere style for long unbroken strings (URLs) so they wrap
        # inside the table cell instead of being truncated with an ellipsis
        url_wrap_s = ParagraphStyle('NXUrlWrap', fontSize=8.5, textColor=colors.HexColor('#00ccff'),
                                    fontName='Courier', wordWrap='CJK', leading=11)

        # ── Header ──────────────────────────────────────────────────────────
        story.append(Paragraph('NEURAL-X', title_s))
        story.append(Paragraph('AI Cyber Defense Platform — Security Report v2', sub_s))
        story.append(HRFlowable(width='100%', thickness=1,
                                color=colors.HexColor('#00ff88')))
        story.append(Spacer(1, 0.3*cm))

        # ── Executive Summary ────────────────────────────────────────────────
        scan_type  = scan_data.get('scan_type', 'url').upper()
        category   = scan_data.get('risk_category', 'Unknown')
        score      = scan_data.get('threat_score', 0)
        url        = scan_data.get('url', 'N/A') or 'N/A'
        domain     = scan_data.get('domain', 'N/A') or 'N/A'
        scan_date  = scan_data.get('scan_date', datetime.utcnow().isoformat())

        story.append(Paragraph('Scan Information', heading_s))
        info_rows = [
            ['Scan Timestamp:', str(scan_date)[:19]],
            ['Target URL:',     Paragraph(url, url_wrap_s)],
            ['Domain:',         domain],
            ['Scan Type:',      scan_type],
        ]
        if scan_data.get('qr_content'):
            info_rows.append(['QR Content:', str(scan_data['qr_content'])[:80]])

        info_t = Table(info_rows, colWidths=[4*cm, 13*cm])
        info_t.setStyle(TableStyle([
            ('FONTNAME',  (0,0),(0,-1), 'Helvetica-Bold'),
            ('FONTSIZE',  (0,0),(-1,-1), 9),
            ('TEXTCOLOR', (0,0),(0,-1), colors.HexColor('#00ccff')),
            ('BOTTOMPADDING', (0,0),(-1,-1), 4),
        ]))
        story.append(info_t)

        # ── Threat / Journal Score ───────────────────────────────────────────
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph('Threat Assessment', heading_s))
        r, g, b = _risk_color_rgb(category)
        rc = colors.Color(r, g, b)

        score_s = ParagraphStyle('Score', fontSize=34, leading=42, alignment=TA_CENTER,
                                 spaceBefore=4, spaceAfter=4,
                                 fontName='Helvetica-Bold', textColor=rc)
        story.append(Paragraph(f'{int(score)}/100', score_s))

        cat_s = ParagraphStyle('Cat', fontSize=16, leading=20, alignment=TA_CENTER,
                               textColor=rc, spaceAfter=10, fontName='Helvetica-Bold')
        story.append(Paragraph(category, cat_s))

        # Hybrid + phishing (v2)
        hybrid = scan_data.get('hybrid_score')
        phish  = scan_data.get('phishing_prob')
        if hybrid is not None or phish is not None:
            extra_rows = []
            if phish is not None:
                extra_rows.append(['Phishing Probability (heuristic):', f'{phish:.1f}%'])
            if hybrid is not None:
                extra_rows.append(['Hybrid Threat Score:', f'{hybrid:.1f}/100'])
            h_t = Table(extra_rows, colWidths=[7*cm, 10*cm])
            h_t.setStyle(TableStyle([
                ('FONTNAME',  (0,0),(0,-1), 'Helvetica-Bold'),
                ('FONTSIZE',  (0,0),(-1,-1), 9),
                ('TEXTCOLOR', (0,0),(0,-1), colors.HexColor('#5a6b78')),
                ('BOTTOMPADDING', (0,0),(-1,-1), 3),
            ]))
            story.append(h_t)
            story.append(Paragraph(
                '* Scores are heuristic estimates based on observable signals, not validated ML accuracy figures.',
                ParagraphStyle('disc', fontSize=7, textColor=colors.HexColor('#6b7a86'), spaceAfter=4)
            ))

        # ── v4: Multi-Signal Risk Breakdown + Prevention Action ──────────────
        final_risk_score = scan_data.get('final_risk_score')
        risk_level        = scan_data.get('risk_level')
        prevention_action = scan_data.get('prevention_action')
        visual_risk        = scan_data.get('visual_risk')
        behavior_risk       = scan_data.get('behavior_risk')
        domain_risk_val      = scan_data.get('domain_risk')

        if final_risk_score is not None or visual_risk is not None or behavior_risk is not None:
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph('Multi-Signal Risk Breakdown', heading_s))

            level_display = {
                'SAFE': 'SAFE', 'LOW_MEDIUM': 'LOW/MEDIUM RISK',
                'HIGH': 'HIGH RISK', 'CRITICAL': 'CRITICAL / PHISHING',
            }.get(risk_level, risk_level or 'N/A')
            action_display = {
                'allow': 'Allowed', 'warn': 'Warning Shown', 'block': 'Blocked',
            }.get(prevention_action, prevention_action or 'N/A')

            def _fmt_score(v):
                return f'{v:.0f}/100' if isinstance(v, (int, float)) else 'Unavailable'

            breakdown_rows = [
                ['URL/ML Risk:',        _fmt_score(scan_data.get('hybrid_score', scan_data.get('threat_score')))],
                ['Domain Risk:',        _fmt_score(domain_risk_val)],
                ['Visual Risk:',        _fmt_score(visual_risk)],
                ['Behavioral Risk:',    _fmt_score(behavior_risk)],
                ['Final Fused Score:',  _fmt_score(final_risk_score)],
                ['Risk Level:',         level_display],
                ['Prevention Action:',  action_display],
            ]
            bt = Table(breakdown_rows, colWidths=[5.5*cm, 11.5*cm])
            bt.setStyle(TableStyle([
                ('FONTNAME',  (0,0),(0,-1), 'Helvetica-Bold'),
                ('FONTSIZE',  (0,0),(-1,-1), 9),
                ('TEXTCOLOR', (0,0),(0,-1), colors.HexColor('#00ccff')),
                ('BOTTOMPADDING', (0,0),(-1,-1), 4),
            ]))
            story.append(bt)

            det_reasons = scan_data.get('detection_reasons') or []
            if det_reasons:
                story.append(Paragraph('Why This Result?', heading_s))
                for r in det_reasons[:20]:
                    story.append(Paragraph(f'✓ {r}', body_s))

            vis_indicators = scan_data.get('visual_indicators') or []
            if vis_indicators and vis_indicators != ['No visual phishing indicators detected']:
                story.append(Paragraph('Visual Analysis Indicators', heading_s))
                for r in vis_indicators[:15]:
                    story.append(Paragraph(f'• {r}', body_s))

            beh_indicators = scan_data.get('behavior_indicators') or []
            if beh_indicators and beh_indicators != ['No suspicious behavioral indicators detected']:
                story.append(Paragraph('Behavioral Analysis Indicators', heading_s))
                for r in beh_indicators[:15]:
                    story.append(Paragraph(f'• {r}', body_s))

            story.append(Paragraph(
                'Visual Risk and Behavioral Risk are heuristic, structural signals '
                '(page markup, forms, scripts, redirects) — not a trained brand-logo '
                'recognition model. A score of "Unavailable" means that module could '
                'not safely analyze the target for this scan.',
                ParagraphStyle('disc2', fontSize=7, textColor=colors.HexColor('#6b7a86'), spaceAfter=4)
            ))

        # ── Journal Section (v2, only when scan_type=journal) ───────────────
        journal_data = scan_data.get('journal_data') or {}
        if isinstance(journal_data, str):
            try:
                journal_data = json.loads(journal_data)
            except Exception:
                journal_data = {}

        if scan_type == 'JOURNAL' and journal_data:
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph('Journal Authenticity Analysis', purple_h))

            j_score = journal_data.get('journal_score', 'N/A')
            auth    = journal_data.get('authenticity_score', 'N/A')
            j_rows  = [
                ['Journal Risk Score:',   f'{j_score}/100 (higher = more suspicious)'],
                ['Authenticity Score:',   f'{auth}/100'],
                ['Risk Classification:',  journal_data.get('risk_category', 'N/A')],
            ]
            j_t = Table(j_rows, colWidths=[5.5*cm, 11.5*cm])
            j_t.setStyle(TableStyle([
                ('FONTNAME',  (0,0),(0,-1), 'Helvetica-Bold'),
                ('FONTSIZE',  (0,0),(-1,-1), 9),
                ('TEXTCOLOR', (0,0),(0,-1), colors.HexColor('#bf60ff')),
                ('BOTTOMPADDING', (0,0),(-1,-1), 4),
            ]))
            story.append(j_t)

            # API check results
            api = journal_data.get('api_checks', {})
            if api:
                story.append(Paragraph('Academic Database Verification', heading_s))
                for db_name, db_res in api.items():
                    if isinstance(db_res, dict) and db_res.get('checked'):
                        status = '✓ FOUND' if db_res.get('found') else '✗ NOT FOUND'
                        detail = db_res.get('title') or db_res.get('member_name') or db_res.get('display_name') or ''
                        story.append(Paragraph(
                            f'<b>{db_name.upper()}:</b> {status} {(" — " + detail[:60]) if detail else ""}',
                            body_s
                        ))

            # Content findings
            cf = journal_data.get('content_findings', {})
            if cf:
                story.append(Paragraph('Content Analysis Findings', heading_s))
                checks = [
                    ('Contact Information', cf.get('has_contact')),
                    ('Editorial Board',     cf.get('has_editorial_board')),
                    ('Ethics Policy',       cf.get('has_ethics_policy')),
                    ('robots.txt',         cf.get('has_robots')),
                    ('Sitemap',            cf.get('has_sitemap')),
                ]
                for label, present in checks:
                    icon = '✓' if present else '✗'
                    story.append(Paragraph(f'{icon} {label}', body_s))

                if cf.get('issns_found'):
                    story.append(Paragraph(
                        f'ISSN Numbers: {", ".join(cf["issns_found"][:6])}', body_s
                    ))
                if cf.get('predatory_keywords'):
                    story.append(Paragraph(
                        f'⚠ Predatory signals: {", ".join(cf["predatory_keywords"][:5])}', body_s
                    ))
                if cf.get('unverified_indexing_claims'):
                    story.append(Paragraph(
                        f'⚠ Unverifiable indexing: {", ".join(cf["unverified_indexing_claims"][:4])}', body_s
                    ))

        # ── Risk Factors ─────────────────────────────────────────────────────
        risk_factors = scan_data.get('risk_factors', [])
        if risk_factors:
            story.append(Paragraph('Risk Factors Detected', heading_s))
            for f in risk_factors[:20]:
                story.append(Paragraph(f'• {f}', body_s))

        # ── Recommendations ──────────────────────────────────────────────────
        recs = scan_data.get('recommendations', [])
        if recs:
            story.append(Paragraph('Security Recommendations', heading_s))
            for rec in recs[:10]:
                story.append(Paragraph(f'✓ {rec}', body_s))

        # ── Screenshot (if available) ─────────────────────────────────────────
        screenshot = scan_data.get('screenshot_path')
        if screenshot:
            full_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                'app', 'static', screenshot
            )
            if os.path.exists(full_path):
                story.append(Paragraph('Website Preview', heading_s))
                try:
                    story.append(RLImage(full_path, width=15*cm, height=8.4*cm))
                except Exception:
                    story.append(Paragraph('Screenshot not renderable in PDF.', body_s))

        # ── Footer ────────────────────────────────────────────────────────────
        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width='100%', thickness=0.5,
                                color=colors.HexColor('#cccccc')))
        story.append(Paragraph(
            f'Generated by NEURAL-X AI Cyber Defense Platform v2 | '
            f'{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC | '
            'This report is for informational purposes only.',
            footer_s
        ))

        doc.build(story, onFirstPage=_add_page_number, onLaterPages=_add_page_number)
        logger.info(f'PDF report generated: {filepath}')
        return relative

    except ImportError:
        logger.warning('reportlab not installed — PDF generation unavailable')
        return None
    except Exception as e:
        logger.error(f'PDF generation failed: {e}')
        return None
