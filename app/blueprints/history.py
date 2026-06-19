"""Scan history blueprint — browse, search, export."""

import csv
import io
import json
from flask import Blueprint, render_template, request, make_response, current_app
from app.models.scan_history import ScanHistory
from app import db

history_bp = Blueprint('history', __name__)


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


@history_bp.route('/export/csv')
def export_csv():
    scans = ScanHistory.query.order_by(ScanHistory.scan_date.desc()).limit(1000).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'URL', 'Domain', 'Threat Score', 'Risk Category',
                     'Scan Type', 'Domain Age (days)', 'SSL Valid', 'QR Content', 'Scan Date'])
    for s in scans:
        writer.writerow([s.id, s.url, s.domain, s.threat_score, s.risk_category,
                         s.scan_type, s.domain_age_days, s.ssl_valid, s.qr_content, s.scan_date])
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=neural-x-history.csv'
    return response


@history_bp.route('/<int:scan_id>')
def detail(scan_id):
    scan = ScanHistory.query.get_or_404(scan_id)
    extra = json.loads(scan.extra_data or '{}')
    return render_template('scan_detail.html', scan=scan, extra=extra)
