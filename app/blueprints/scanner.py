"""Scanner blueprint — URL, QR, and image scan routes."""

import os
import json
import uuid
import logging
from datetime import datetime
from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, current_app, jsonify)
from werkzeug.utils import secure_filename
from app import db
from app.models.scan_history import ScanHistory
from app.models.threat_report import ThreatReport
from app.services.url_analyzer import analyze_url
from app.services.qr_analyzer import analyze_qr_image
from app.services.image_analyzer import analyze_image
from app.services.domain_intel import get_domain_intelligence, extract_domain
from app.services.screenshot_service import capture_screenshot
from app.utils.helpers import allowed_file, sanitize_url

scanner_bp = Blueprint('scanner', __name__)
logger = logging.getLogger(__name__)


def _save_scan(url, threat_score, risk_category, scan_type='url',
               qr_content=None, domain_age=None, ssl_valid=None,
               screenshot_path=None, risk_factors=None, recommendations=None,
               domain=None):
    """Persist a scan result to the database."""
    scan = ScanHistory(
        url=url,
        domain=domain or (extract_domain(url) if url else None),
        threat_score=threat_score,
        risk_category=risk_category,
        scan_type=scan_type,
        qr_content=qr_content,
        domain_age_days=domain_age,
        ssl_valid=ssl_valid,
        screenshot_path=screenshot_path,
        scan_date=datetime.utcnow(),
        extra_data=json.dumps({
            'risk_factors': risk_factors or [],
            'recommendations': recommendations or [],
        }),
    )
    db.session.add(scan)
    db.session.flush()

    report = ThreatReport(
        scan_id=scan.id,
        risk_factors=json.dumps(risk_factors or []),
        recommendations=json.dumps(recommendations or []),
    )
    db.session.add(report)
    db.session.commit()
    return scan


# ------------------------------------------------------------------
# URL Scanner
# ------------------------------------------------------------------
@scanner_bp.route('/url', methods=['GET', 'POST'])
def scan_url():
    if request.method == 'GET':
        return render_template('scan_url.html')

    url = sanitize_url(request.form.get('url', '').strip())
    if not url:
        flash('Please enter a valid URL.', 'error')
        return render_template('scan_url.html')

    # Run analysis pipeline
    url_result = analyze_url(url)
    domain = extract_domain(url)

    # Domain intelligence
    domain_info = {}
    try:
        domain_info = get_domain_intelligence(url)
        url_result['risk_factors'].extend(domain_info.get('risk_factors', []))
    except Exception as e:
        logger.warning(f'Domain intel failed: {e}')

    # Screenshot (non-blocking — skip if slow)
    screenshot_path = None
    try:
        timeout = current_app.config.get('SCREENSHOT_TIMEOUT', 15)
        screenshot_path = capture_screenshot(url, timeout=timeout)
    except Exception as e:
        logger.debug(f'Screenshot skipped: {e}')

    # Reputation feeds
    reputation = {}
    try:
        from app.services.reputation_service import get_reputation_verdict
        reputation = get_reputation_verdict(url, current_app.config)
        url_result['risk_factors'].extend(reputation.get('risk_factors', []))
        # Merge reputation score into threat score
        combined = (url_result['threat_score'] * 0.6 +
                    reputation.get('reputation_score', 0) * 0.4)
        url_result['threat_score'] = min(100, round(combined, 1))
    except Exception as e:
        logger.debug(f'Reputation check skipped: {e}')

    # Recalculate category after merging
    score = url_result['threat_score']
    if score < 20:
        url_result['risk_category'] = 'Safe'
    elif score < 45:
        url_result['risk_category'] = 'Suspicious'
    elif score < 70:
        url_result['risk_category'] = 'High Risk'
    else:
        url_result['risk_category'] = 'Critical Threat'

    domain_age = domain_info.get('domain_age_days')
    ssl_valid = domain_info.get('ssl', {}).get('valid')

    scan = _save_scan(
        url=url,
        threat_score=url_result['threat_score'],
        risk_category=url_result['risk_category'],
        scan_type='url',
        domain_age=domain_age,
        ssl_valid=ssl_valid,
        screenshot_path=screenshot_path,
        risk_factors=url_result.get('risk_factors', []),
        recommendations=url_result.get('recommendations', []),
        domain=domain,
    )

    return render_template('result.html',
                           scan=scan,
                           url_result=url_result,
                           domain_info=domain_info,
                           reputation=reputation,
                           screenshot_path=screenshot_path)


# ------------------------------------------------------------------
# QR Scanner
# ------------------------------------------------------------------
@scanner_bp.route('/qr', methods=['GET', 'POST'])
def scan_qr():
    if request.method == 'GET':
        return render_template('scan_qr.html')

    if 'qr_file' not in request.files:
        flash('No file uploaded.', 'error')
        return render_template('scan_qr.html')

    file = request.files['qr_file']
    if not file or not allowed_file(file.filename, current_app.config['ALLOWED_IMAGE_EXTENSIONS']):
        flash('Invalid file type. Please upload PNG, JPG, GIF, BMP, or WEBP.', 'error')
        return render_template('scan_qr.html')

    # Save uploaded file
    upload_dir = current_app.config['UPLOAD_DIR']
    filename = f'qr_{uuid.uuid4().hex[:12]}_{secure_filename(file.filename)}'
    filepath = os.path.join(upload_dir, filename)
    file.save(filepath)

    # Analyze QR
    qr_result = analyze_qr_image(filepath)

    # If URL, get domain intel too
    domain_info = {}
    if qr_result.get('url_analysis'):
        try:
            url = qr_result['classification']['parsed_data'].get('url', '')
            domain_info = get_domain_intelligence(url)
        except Exception:
            pass

    scan = _save_scan(
        url=qr_result.get('url_analysis', {}).get('url') if qr_result.get('url_analysis') else None,
        threat_score=qr_result.get('threat_score', 0),
        risk_category=qr_result.get('risk_category', 'Safe'),
        scan_type='qr',
        qr_content=qr_result.get('raw_content'),
        risk_factors=qr_result.get('risk_factors', []),
    )

    # Clean up uploaded file
    try:
        os.remove(filepath)
    except Exception:
        pass

    return render_template('result_qr.html',
                           scan=scan,
                           qr_result=qr_result,
                           domain_info=domain_info)


# ------------------------------------------------------------------
# Image Scanner
# ------------------------------------------------------------------
@scanner_bp.route('/image', methods=['GET', 'POST'])
def scan_image():
    if request.method == 'GET':
        return render_template('scan_image.html')

    if 'image_file' not in request.files:
        flash('No image uploaded.', 'error')
        return render_template('scan_image.html')

    file = request.files['image_file']
    if not file or not allowed_file(file.filename, current_app.config['ALLOWED_IMAGE_EXTENSIONS']):
        flash('Invalid file type.', 'error')
        return render_template('scan_image.html')

    upload_dir = current_app.config['UPLOAD_DIR']
    filename = f'img_{uuid.uuid4().hex[:12]}_{secure_filename(file.filename)}'
    filepath = os.path.join(upload_dir, filename)
    file.save(filepath)

    image_result = analyze_image(filepath)

    scan = _save_scan(
        url=None,
        threat_score=image_result.get('threat_score', 0),
        risk_category=image_result.get('risk_category', 'Safe'),
        scan_type='image',
        risk_factors=image_result.get('risk_factors', []),
        recommendations=image_result.get('recommendations', []),
    )

    try:
        os.remove(filepath)
    except Exception:
        pass

    return render_template('result_image.html',
                           scan=scan,
                           image_result=image_result)
