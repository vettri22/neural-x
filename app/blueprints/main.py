<<<<<<< HEAD
"""Main blueprint — landing page and dashboard. v2: adds journal scan stats."""
=======
"""Main blueprint — landing page and dashboard."""
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f

from flask import Blueprint, render_template
from app.models.scan_history import ScanHistory
from app import db
<<<<<<< HEAD
=======
from sqlalchemy import func
from datetime import datetime, timedelta
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
<<<<<<< HEAD
    total_scans    = ScanHistory.query.count()
    threats_blocked = ScanHistory.query.filter(
        ScanHistory.risk_category.in_(['High Risk', 'Critical Threat'])
    ).count()
    safe_scans     = ScanHistory.query.filter_by(risk_category='Safe').count()
    suspicious_scans = ScanHistory.query.filter_by(risk_category='Suspicious').count()
    journal_scans  = ScanHistory.query.filter_by(scan_type='journal').count()
=======
    """Landing page with cyber dashboard overview."""
    total_scans = ScanHistory.query.count()
    threats_blocked = ScanHistory.query.filter(
        ScanHistory.risk_category.in_(['High Risk', 'Critical Threat'])
    ).count()
    safe_scans = ScanHistory.query.filter_by(risk_category='Safe').count()
    suspicious_scans = ScanHistory.query.filter_by(risk_category='Suspicious').count()
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f

    recent_scans = ScanHistory.query.order_by(ScanHistory.scan_date.desc()).limit(5).all()

    stats = {
<<<<<<< HEAD
        'total_scans':     total_scans,
        'threats_blocked': threats_blocked,
        'safe_scans':      safe_scans,
        'suspicious_scans':suspicious_scans,
        'journal_scans':   journal_scans,
    }
=======
        'total_scans': total_scans,
        'threats_blocked': threats_blocked,
        'safe_scans': safe_scans,
        'suspicious_scans': suspicious_scans,
    }

>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
    return render_template('index.html', stats=stats, recent_scans=recent_scans)


@main_bp.route('/dashboard')
def dashboard():
<<<<<<< HEAD
    return render_template('index.html',
                           stats={'total_scans':0,'threats_blocked':0,'safe_scans':0,'suspicious_scans':0,'journal_scans':0},
                           recent_scans=[])
=======
    return render_template('dashboard.html')
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
