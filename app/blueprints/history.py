"""Scan history blueprint — browse, search, export."""

import csv
import io
import json
import logging
from datetime import datetime
from flask import (Blueprint, render_template, request, make_response,
                   current_app, Response, send_file, abort)
from app.models.scan_history import ScanHistory
from app import db

history_bp = Blueprint('history', __name__)
logger = logging.getLogger(__name__)

# Hard export cap so a single request can't be used to exhaust memory/DB.
MAX_EXPORT_ROWS = 50000


def _build_history_query():
    """Shared query builder — export honors the same search/filter params
    as the history browser so 'export what I'm looking at' works."""
    search = request.args.get('q', '').strip()
    category = request.args.get('category', '')
    scan_type = request.args.get('type', '')

    q = ScanHistory.query
    if search:
        q = q.filter(ScanHistory.url.ilike(f'%{search}%') |
                     ScanHistory.domain.ilike(f'%{search}%'))
    if category:
        q = q.filter_by(risk_category=category)
    if scan_type:
        q = q.filter_by(scan_type=scan_type)
    return q


@history_bp.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('q', '').strip()
    category = request.args.get('category', '')
    scan_type = request.args.get('type', '')
    per_page = current_app.config.get('HISTORY_PER_PAGE', 20)

    q = ScanHistory.query
    if search:
        q = q.filter(ScanHistory.url.ilike(f'%{search}%') |
                     ScanHistory.domain.ilike(f'%{search}%'))
    if category:
        q = q.filter_by(risk_category=category)
    if scan_type:
        q = q.filter_by(scan_type=scan_type)

    pagination = q.order_by(ScanHistory.scan_date.desc()).paginate(
        page=page, per_page=per_page, error_out=False)

    return render_template('history.html',
                           scans=pagination.items,
                           pagination=pagination,
                           search=search,
                           category=category,
                           scan_type=scan_type)


CSV_HEADERS = [
    'ID', 'URL', 'Domain', 'Scan Type', 'Scan Date (UTC)',
    'Final Risk Score', 'Risk Level', 'Prevention Action',
    'URL/ML Risk', 'Domain Risk', 'Visual Risk', 'Behavioral Risk',
    'Legacy Threat Score', 'Legacy Risk Category',
    'Journal Score', 'Hybrid Score', 'Phishing Probability (%)',
    'Domain Age (days)', 'SSL Valid', 'QR Content',
    'Detection Reasons',
]


def _row_for_scan(s: ScanHistory):
    def _fmt(v):
        return '' if v is None else v

    reasons = []
    try:
        reasons = json.loads(s.detection_reasons) if s.detection_reasons else []
    except (TypeError, ValueError):
        reasons = []
    if not reasons and s.extra_data:
        try:
            reasons = json.loads(s.extra_data).get('risk_factors', [])
        except (TypeError, ValueError):
            reasons = []

    return [
        s.id,
        s.url,
        s.domain,
        s.scan_type,
        s.scan_date.strftime('%Y-%m-%d %H:%M:%S') if s.scan_date else '',
        _fmt(s.final_risk_score),
        _fmt(s.risk_level),
        _fmt(s.prevention_action),
        _fmt(s.hybrid_score if s.hybrid_score is not None else s.threat_score),
        _fmt(s.domain_risk),
        _fmt(s.visual_risk),
        _fmt(s.behavior_risk),
        _fmt(s.threat_score),
        _fmt(s.risk_category),
        _fmt(s.journal_score),
        _fmt(s.hybrid_score),
        _fmt(s.phishing_prob),
        _fmt(s.domain_age_days),
        _fmt(s.ssl_valid),
        _fmt(s.qr_content),
        '; '.join(reasons) if reasons else '',
    ]


@history_bp.route('/export/csv')
def export_csv():
    """
    Export scan history as CSV.

    Root-cause fixes applied here vs. the original implementation:
      - Original export only wrote 10 legacy columns and silently omitted
        every v2/v3/v4 score (journal_score, hybrid_score, phishing_prob,
        visual/behavioral/final risk, risk level, detection reasons) even
        though those columns already existed on the model — so the
        downloaded file never matched what the dashboard actually showed.
      - No UTF-8 BOM was written, so Excel on Windows mis-renders
        non-ASCII characters (common in IDN/punycode phishing domains).
      - The route ignored the history page's active search/filter, so
        "export" always dumped the unfiltered table.
      - A silent `.limit(1000)` truncated large histories with no
        indication to the user that data was missing.
    Fixes: full column set, UTF-8 BOM, honors current filters, streams the
    query in chunks (works for empty and very large datasets alike) and
    caps at MAX_EXPORT_ROWS with a logged warning rather than an
    unexplained silent truncation.
    """
    query = _build_history_query().order_by(ScanHistory.scan_date.desc())

    def generate():
        yield '\ufeff'  # UTF-8 BOM so Excel renders non-ASCII domains correctly
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(CSV_HEADERS)
        yield buf.getvalue()
        buf.seek(0); buf.truncate(0)

        count = 0
        for scan in query.yield_per(500).limit(MAX_EXPORT_ROWS):
            writer.writerow(_row_for_scan(scan))
            count += 1
            if count % 500 == 0:
                yield buf.getvalue()
                buf.seek(0); buf.truncate(0)
        if buf.tell():
            yield buf.getvalue()

        if count == MAX_EXPORT_ROWS:
            logger.warning(f'CSV export truncated at {MAX_EXPORT_ROWS} rows')

    filename = f'neural-x-history-{datetime.utcnow().strftime("%Y%m%d-%H%M%S")}.csv'
    response = Response(generate(), mimetype='text/csv; charset=utf-8')
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


@history_bp.route('/<int:scan_id>/export/pdf')
def export_pdf(scan_id):
    """
    Direct-download PDF export for a single scan.

    Root-cause fix: the frontend's "Download PDF Report" buttons previously
    linked straight to /api/report/<id>, which returns a JSON envelope
    ({"pdf_url": ...}) rather than a file — so clicking the button opened
    JSON text instead of downloading anything. This route generates the PDF
    from the REAL scan record and streams the actual file back with a
    Content-Disposition: attachment header, so the browser downloads it.
    """
    scan = ScanHistory.query.get_or_404(scan_id)
    extra = json.loads(scan.extra_data or '{}')

    try:
        detection_reasons = json.loads(scan.detection_reasons) if scan.detection_reasons else []
    except (TypeError, ValueError):
        detection_reasons = []
    try:
        visual_indicators = json.loads(scan.visual_indicators) if scan.visual_indicators else []
    except (TypeError, ValueError):
        visual_indicators = []
    try:
        behavior_indicators = json.loads(scan.behavior_indicators) if scan.behavior_indicators else []
    except (TypeError, ValueError):
        behavior_indicators = []

    from app.services.pdf_report import generate_pdf_report
    pdf_relpath = generate_pdf_report({
        'id':             scan.id,
        'url':            scan.url,
        'domain':         scan.domain,
        'threat_score':   scan.threat_score,
        'risk_category':  scan.risk_category,
        'scan_date':      scan.scan_date.isoformat() if scan.scan_date else '',
        'scan_type':      scan.scan_type,
        'qr_content':     scan.qr_content,
        'risk_factors':   extra.get('risk_factors', []),
        'recommendations':extra.get('recommendations', []),
        'screenshot_path':scan.screenshot_path,
        'journal_score':  scan.journal_score,
        'hybrid_score':   scan.hybrid_score,
        'phishing_prob':  scan.phishing_prob,
        'journal_data':   json.loads(scan.journal_data) if scan.journal_data else {},
        # v4
        'visual_risk':          scan.visual_risk,
        'visual_indicators':    visual_indicators,
        'behavior_risk':        scan.behavior_risk,
        'behavior_indicators':  behavior_indicators,
        'domain_risk':          scan.domain_risk,
        'final_risk_score':     scan.final_risk_score,
        'risk_level':           scan.risk_level,
        'prevention_action':    scan.prevention_action,
        'detection_reasons':    detection_reasons,
    })

    if not pdf_relpath:
        abort(500, description='PDF generation failed (reportlab may not be installed).')

    import os as _os
    pdf_full_path = _os.path.join(current_app.root_path, 'static', pdf_relpath)

    return send_file(
        pdf_full_path,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'neural-x-report-scan-{scan.id}.pdf',
    )


@history_bp.route('/<int:scan_id>')
def detail(scan_id):
    scan = ScanHistory.query.get_or_404(scan_id)
    extra = json.loads(scan.extra_data or '{}')
    return render_template('scan_detail.html', scan=scan, extra=extra)
