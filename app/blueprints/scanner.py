<<<<<<< HEAD
"""
Scanner Blueprint — URL, QR, Image, and Journal scan routes.
v2: adds Journal Authenticity Verification + Hybrid Scoring.
All existing routes and signatures preserved.
"""
=======
"""Scanner blueprint — URL, QR, and image scan routes."""
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f

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


<<<<<<< HEAD
# ── internal helpers ────────────────────────────────────────────────────────

def _save_scan(url, threat_score, risk_category, scan_type='url',
               qr_content=None, domain_age=None, ssl_valid=None,
               screenshot_path=None, risk_factors=None, recommendations=None,
               domain=None, journal_score=None, journal_data=None,
               hybrid_score=None, phishing_prob=None,
               visual_risk=None, visual_indicators=None,
               behavior_risk=None, behavior_indicators=None,
               domain_risk=None, final_risk_score=None, risk_level=None,
               detection_reasons=None, prevention_action=None):
    """Persist a scan result to the database (backwards-compatible with v1)."""
=======
def _save_scan(url, threat_score, risk_category, scan_type='url',
               qr_content=None, domain_age=None, ssl_valid=None,
               screenshot_path=None, risk_factors=None, recommendations=None,
               domain=None):
    """Persist a scan result to the database."""
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
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
<<<<<<< HEAD
            'risk_factors':    risk_factors or [],
            'recommendations': recommendations or [],
        }),
        # v2 fields
        journal_score=journal_score,
        journal_data=json.dumps(journal_data) if journal_data else None,
        hybrid_score=hybrid_score,
        phishing_prob=phishing_prob,
        # v4 fields — Visual / Behavioral / Final Fusion
        visual_risk=visual_risk,
        visual_indicators=json.dumps(visual_indicators) if visual_indicators is not None else None,
        behavior_risk=behavior_risk,
        behavior_indicators=json.dumps(behavior_indicators) if behavior_indicators is not None else None,
        domain_risk=domain_risk,
        final_risk_score=final_risk_score,
        risk_level=risk_level,
        detection_reasons=json.dumps(detection_reasons) if detection_reasons is not None else None,
        prevention_action=prevention_action,
=======
            'risk_factors': risk_factors or [],
            'recommendations': recommendations or [],
        }),
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
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


<<<<<<< HEAD
def _run_reputation(url, url_result):
    """Run reputation feeds and merge into url_result. Returns reputation dict."""
    reputation = {}
    try:
        from app.services.reputation_service import get_reputation_verdict
        reputation = get_reputation_verdict(url, current_app.config)
        url_result['risk_factors'].extend(reputation.get('risk_factors', []))
        combined = (url_result['threat_score'] * 0.6 +
                    reputation.get('reputation_score', 0) * 0.4)
        url_result['threat_score'] = min(100, round(combined, 1))
    except Exception as e:
        logger.debug(f'Reputation check skipped: {e}')
    return reputation


def _run_domain_intel(url, url_result):
    """Run domain intelligence. Returns domain_info dict."""
    domain_info = {}
    try:
        domain_info = get_domain_intelligence(url)
        url_result['risk_factors'].extend(domain_info.get('risk_factors', []))
    except Exception as e:
        logger.warning(f'Domain intel failed: {e}')
    return domain_info


def _run_screenshot(url):
    """Capture screenshot non-blocking. Returns path or None."""
    try:
        timeout = current_app.config.get('SCREENSHOT_TIMEOUT', 15)
        return capture_screenshot(url, timeout=timeout)
    except Exception as e:
        logger.debug(f'Screenshot skipped: {e}')
        return None


def _recalc_category(score):
    if score < 20:   return 'Safe'
    if score < 45:   return 'Suspicious'
    if score < 70:   return 'High Risk'
    return 'Critical Threat'


def _run_hybrid(url_result, domain_info, reputation, journal_result=None):
    """Run hybrid scorer. Returns hybrid dict or empty dict on failure."""
    try:
        from app.services.hybrid_scorer import compute_hybrid_score
        return compute_hybrid_score(url_result, domain_info, reputation,
                                    journal_result=journal_result)
    except Exception as e:
        logger.debug(f'Hybrid scorer failed: {e}')
        return {}


def _run_visual(url, domain, screenshot_path):
    """Run the visual/brand-impersonation analyzer. Never raises."""
    try:
        from app.services.visual_analyzer import analyze_visual
        return analyze_visual(url, domain, screenshot_path)
    except Exception as e:
        logger.warning(f'Visual analysis unavailable: {e}')
        return {'available': False, 'visual_score': None, 'indicators': [],
                'screenshot_path': screenshot_path, 'unavailable_reason': str(e)}


def _run_behavior(url):
    """Run the behavioral analyzer. Never raises."""
    try:
        from app.services.behavior_analyzer import analyze_behavior
        return analyze_behavior(url)
    except Exception as e:
        logger.warning(f'Behavioral analysis unavailable: {e}')
        return {'available': False, 'behavior_score': None, 'indicators': [],
                'redirect_count': 0, 'final_url': None, 'unavailable_reason': str(e)}


def _run_final_fusion(url_ml_score, domain_score, visual_result, behavior_result):
    """Run the v4 multi-signal risk fusion engine. Never raises."""
    try:
        from app.services.risk_fusion import compute_final_risk
        weights = current_app.config.get('RISK_FUSION_WEIGHTS')
        thresholds = current_app.config.get('RISK_LEVEL_THRESHOLDS')
        return compute_final_risk(url_ml_score, domain_score, visual_result,
                                  behavior_result, weights=weights, thresholds=thresholds)
    except Exception as e:
        logger.warning(f'Risk fusion failed: {e}')
        return {'final_score': None, 'risk_level': 'UNKNOWN',
                'risk_level_display': 'UNKNOWN — ANALYSIS UNAVAILABLE',
                'prevention_action': 'warn', 'signals': {}, 'reasons': [], 'weights_used': {}}


# ── URL Scanner (unchanged route) ───────────────────────────────────────────

=======
# ------------------------------------------------------------------
# URL Scanner
# ------------------------------------------------------------------
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
@scanner_bp.route('/url', methods=['GET', 'POST'])
def scan_url():
    if request.method == 'GET':
        return render_template('scan_url.html')

    url = sanitize_url(request.form.get('url', '').strip())
    if not url:
        flash('Please enter a valid URL.', 'error')
        return render_template('scan_url.html')

<<<<<<< HEAD
    url_result  = analyze_url(url)
    domain      = extract_domain(url)
    domain_info = _run_domain_intel(url, url_result)
    screenshot_path = _run_screenshot(url)
    reputation  = _run_reputation(url, url_result)

    url_result['threat_score']  = min(100, round(url_result['threat_score'], 1))
    url_result['risk_category'] = _recalc_category(url_result['threat_score'])

    # v3: classify website first, then run journal analyzer only if appropriate
    journal_result = None
    try:
        from app.services.journal_analyzer import analyze_journal, is_journal_url
        from app.services.website_classifier import classify_website
        classification = classify_website(url)
        if classification.get('should_run_journal_checks', True) or classification.get('is_known_safe'):
            journal_result = analyze_journal(url, domain_info)
            # Only merge risk factors if not a known-safe platform
            if not journal_result.get('is_known_safe'):
                url_result['risk_factors'].extend(journal_result.get('risk_factors', []))
    except Exception as e:
        logger.debug(f'Journal analyzer skipped: {e}')

    hybrid = _run_hybrid(url_result, domain_info, reputation, journal_result)

    # v4: Visual Phishing Detection + Behavioral Analysis + Multi-Signal Fusion.
    # Each module is independently fault-tolerant — a failure here never
    # aborts the scan; it just reports that signal as unavailable.
    visual_result   = _run_visual(url, domain, screenshot_path)
    behavior_result = _run_behavior(url)

    url_ml_score = hybrid.get('final_score', url_result['threat_score'])
    domain_score = hybrid.get('sub_scores', {}).get('domain_intel')
    final_risk = _run_final_fusion(url_ml_score, domain_score, visual_result, behavior_result)

    scan = _save_scan(
        url=url, threat_score=url_result['threat_score'],
        risk_category=url_result['risk_category'],
        # Root-cause fix: this route is the generic URL/website scanner —
        # journal_analyzer runs here only as a background ENRICHMENT signal
        # (it feeds journal_score/journal_data into the hybrid score) and is
        # NOT an indication the user submitted a journal. The previous logic
        # `'journal' if journal_result else 'url'` mislabeled almost every
        # scan as "journal" because the classifier defaults to running
        # journal checks on most sites. scan_type must reflect what was
        # actually scanned (a URL), not which enrichment modules fired.
        # The dedicated /scan/journal route below still saves scan_type='journal'.
        scan_type='url',
        domain_age=domain_info.get('domain_age_days'),
        ssl_valid=domain_info.get('ssl', {}).get('valid'),
=======
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
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
        screenshot_path=screenshot_path,
        risk_factors=url_result.get('risk_factors', []),
        recommendations=url_result.get('recommendations', []),
        domain=domain,
<<<<<<< HEAD
        journal_score=journal_result.get('journal_score') if journal_result else None,
        journal_data=journal_result,
        hybrid_score=hybrid.get('final_score'),
        phishing_prob=hybrid.get('phishing_probability'),
        # v4
        visual_risk=visual_result.get('visual_score'),
        visual_indicators=visual_result.get('indicators'),
        behavior_risk=behavior_result.get('behavior_score'),
        behavior_indicators=behavior_result.get('indicators'),
        domain_risk=domain_score,
        final_risk_score=final_risk.get('final_score'),
        risk_level=final_risk.get('risk_level'),
        detection_reasons=final_risk.get('reasons'),
        prevention_action=final_risk.get('prevention_action'),
    )

    return render_template(
        'result.html',
        scan=scan,
        url_result=url_result,
        domain_info=domain_info,
        reputation=reputation,
        screenshot_path=screenshot_path,
        journal_result=journal_result,
        hybrid=hybrid,
        visual_result=visual_result,
        behavior_result=behavior_result,
        final_risk=final_risk,
    )


# ── Journal Scanner (new dedicated route) ───────────────────────────────────

@scanner_bp.route('/journal', methods=['GET', 'POST'])
def scan_journal():
    if request.method == 'GET':
        return render_template('scan_journal.html')

    url = sanitize_url(request.form.get('url', '').strip())
    if not url:
        flash('Please enter a journal or publisher URL.', 'error')
        return render_template('scan_journal.html')

    # Full pipeline
    url_result  = analyze_url(url)
    domain      = extract_domain(url)
    domain_info = _run_domain_intel(url, url_result)
    reputation  = _run_reputation(url, url_result)
    screenshot_path = _run_screenshot(url)

    # v3: Classify first, then run full journal analysis
    journal_result = {}
    try:
        from app.services.journal_analyzer import analyze_journal
        from app.services.website_classifier import classify_website
        journal_result = analyze_journal(url, domain_info)
        if not journal_result.get('is_known_safe'):
            url_result['risk_factors'].extend(journal_result.get('risk_factors', []))
    except Exception as e:
        logger.warning(f'Journal analyzer error: {e}')
        journal_result = {'error': str(e), 'risk_category': 'Unknown'}

    # Use journal score as primary threat score on this route
    final_score = journal_result.get('journal_score', url_result['threat_score'])
    risk_category = journal_result.get('risk_category', _recalc_category(final_score))

    hybrid = _run_hybrid(url_result, domain_info, reputation, journal_result)

    visual_result   = _run_visual(url, domain, screenshot_path)
    behavior_result = _run_behavior(url)
    domain_score = hybrid.get('sub_scores', {}).get('domain_intel')
    final_risk = _run_final_fusion(hybrid.get('final_score', final_score),
                                   domain_score, visual_result, behavior_result)

    scan = _save_scan(
        url=url, threat_score=final_score, risk_category=risk_category,
        scan_type='journal',
        domain_age=domain_info.get('domain_age_days'),
        ssl_valid=domain_info.get('ssl', {}).get('valid'),
        screenshot_path=screenshot_path,
        risk_factors=url_result.get('risk_factors', []),
        recommendations=journal_result.get('recommendations', []),
        domain=domain,
        journal_score=journal_result.get('journal_score'),
        journal_data=journal_result,
        hybrid_score=hybrid.get('final_score'),
        phishing_prob=hybrid.get('phishing_probability'),
        visual_risk=visual_result.get('visual_score'),
        visual_indicators=visual_result.get('indicators'),
        behavior_risk=behavior_result.get('behavior_score'),
        behavior_indicators=behavior_result.get('indicators'),
        domain_risk=domain_score,
        final_risk_score=final_risk.get('final_score'),
        risk_level=final_risk.get('risk_level'),
        detection_reasons=final_risk.get('reasons'),
        prevention_action=final_risk.get('prevention_action'),
    )

    return render_template(
        'result_journal.html',
        scan=scan,
        url_result=url_result,
        domain_info=domain_info,
        reputation=reputation,
        screenshot_path=screenshot_path,
        journal_result=journal_result,
        hybrid=hybrid,
        visual_result=visual_result,
        behavior_result=behavior_result,
        final_risk=final_risk,
    )


# ── QR Scanner (unchanged route — preserved exactly) ────────────────────────

=======
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
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
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

<<<<<<< HEAD
=======
    # Save uploaded file
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
    upload_dir = current_app.config['UPLOAD_DIR']
    filename = f'qr_{uuid.uuid4().hex[:12]}_{secure_filename(file.filename)}'
    filepath = os.path.join(upload_dir, filename)
    file.save(filepath)

<<<<<<< HEAD
    qr_result = analyze_qr_image(filepath)

    domain_info = {}
    if qr_result.get('url_analysis'):
        try:
            qr_url = qr_result['classification']['parsed_data'].get('url', '')
            if qr_url:
                domain_info = get_domain_intelligence(qr_url)
=======
    # Analyze QR
    qr_result = analyze_qr_image(filepath)

    # If URL, get domain intel too
    domain_info = {}
    if qr_result.get('url_analysis'):
        try:
            url = qr_result['classification']['parsed_data'].get('url', '')
            domain_info = get_domain_intelligence(url)
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
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

<<<<<<< HEAD
=======
    # Clean up uploaded file
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
    try:
        os.remove(filepath)
    except Exception:
        pass

<<<<<<< HEAD
    return render_template('result_qr.html', scan=scan, qr_result=qr_result, domain_info=domain_info)


# ── Image Scanner (unchanged route — preserved exactly) ─────────────────────

=======
    return render_template('result_qr.html',
                           scan=scan,
                           qr_result=qr_result,
                           domain_info=domain_info)


# ------------------------------------------------------------------
# Image Scanner
# ------------------------------------------------------------------
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
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

<<<<<<< HEAD
    return render_template('result_image.html', scan=scan, image_result=image_result)
=======
    return render_template('result_image.html',
                           scan=scan,
                           image_result=image_result)
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
