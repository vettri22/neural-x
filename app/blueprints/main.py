"""Main blueprint — landing page and dashboard."""

from flask import Blueprint, render_template
from app.models.scan_history import ScanHistory
from app import db
from sqlalchemy import func
from datetime import datetime, timedelta

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    """Landing page with cyber dashboard overview."""
    total_scans = ScanHistory.query.count()
    threats_blocked = ScanHistory.query.filter(
        ScanHistory.risk_category.in_(['High Risk', 'Critical Threat'])
    ).count()
    safe_scans = ScanHistory.query.filter_by(risk_category='Safe').count()
    suspicious_scans = ScanHistory.query.filter_by(risk_category='Suspicious').count()

    recent_scans = ScanHistory.query.order_by(ScanHistory.scan_date.desc()).limit(5).all()

    stats = {
        'total_scans': total_scans,
        'threats_blocked': threats_blocked,
        'safe_scans': safe_scans,
        'suspicious_scans': suspicious_scans,
    }

    return render_template('index.html', stats=stats, recent_scans=recent_scans)


@main_bp.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')
