"""Admin dashboard blueprint."""

import json
from datetime import datetime, timedelta
from flask import Blueprint, render_template
from sqlalchemy import func
from app import db
from app.models.scan_history import ScanHistory

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/')
def dashboard():
    total_scans = ScanHistory.query.count()
    threats_blocked = ScanHistory.query.filter(
        ScanHistory.risk_category.in_(['High Risk', 'Critical Threat'])
    ).count()
    safe_scans = ScanHistory.query.filter_by(risk_category='Safe').count()
    suspicious_scans = ScanHistory.query.filter_by(risk_category='Suspicious').count()

    # Top malicious domains
    top_domains = (
        db.session.query(ScanHistory.domain, func.count(ScanHistory.id).label('count'))
        .filter(ScanHistory.risk_category.in_(['High Risk', 'Critical Threat']))
        .filter(ScanHistory.domain != None)
        .group_by(ScanHistory.domain)
        .order_by(func.count(ScanHistory.id).desc())
        .limit(10)
        .all()
    )

    # Daily activity last 30 days
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    daily_scans = (
        db.session.query(
            func.date(ScanHistory.scan_date).label('day'),
            func.count(ScanHistory.id).label('count')
        )
        .filter(ScanHistory.scan_date >= thirty_days_ago)
        .group_by(func.date(ScanHistory.scan_date))
        .order_by(func.date(ScanHistory.scan_date))
        .all()
    )

    daily_labels = [str(row.day) for row in daily_scans]
    daily_counts = [row.count for row in daily_scans]

    # Scan type breakdown
    scan_types = {}
    for t in ['url', 'qr', 'image']:
        scan_types[t] = ScanHistory.query.filter_by(scan_type=t).count()

    stats = {
        'total_scans': total_scans,
        'threats_blocked': threats_blocked,
        'safe_scans': safe_scans,
        'suspicious_scans': suspicious_scans,
        'scan_types': scan_types,
    }

    return render_template('admin/dashboard.html',
                           stats=stats,
                           top_domains=top_domains,
                           daily_labels=json.dumps(daily_labels),
                           daily_counts=json.dumps(daily_counts))
