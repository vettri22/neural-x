"""
REST API Blueprint — /api/*
<<<<<<< HEAD
v2: adds /api/scan-journal, /api/journal-check endpoints.
All existing v1 endpoints preserved with identical signatures.
=======
Provides JSON endpoints for all scan operations.
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
"""

import os
import json
import uuid
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename
from app import db, limiter
from app.models.scan_history import ScanHistory
from app.services.url_analyzer import analyze_url
from app.services.qr_analyzer import analyze_qr_image
from app.services.image_analyzer import analyze_image
from app.services.domain_intel import get_domain_intelligence, extract_domain
from app.utils.helpers import allowed_file, sanitize_url

api_bp = Blueprint('api', __name__)
logger = logging.getLogger(__name__)


def _api_response(data=None, message='OK', status=200, error=None):
    payload = {'status': 'success' if not error else 'error', 'message': message}
    if data is not None:
        payload['data'] = data
    if error:
        payload['error'] = error
    return jsonify(payload), status


<<<<<<< HEAD
# ── /api/scan-url  (v1 preserved) ──────────────────────────────────────────
=======
# ── /api/scan-url ──────────────────────────────────────────────────────────
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
@api_bp.route('/scan-url', methods=['POST'])
@limiter.limit('30 per minute')
def api_scan_url():
    body = request.get_json(silent=True) or {}
<<<<<<< HEAD
    url  = sanitize_url(body.get('url', '').strip())
    if not url:
        return _api_response(error='URL is required', status=400)

    result      = analyze_url(url)
    domain      = extract_domain(url)
=======
    url = sanitize_url(body.get('url', '').strip())
    if not url:
        return _api_response(error='URL is required', status=400)

    result = analyze_url(url)
    domain = extract_domain(url)

>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
    domain_info = {}
    try:
        domain_info = get_domain_intelligence(url)
        result['risk_factors'].extend(domain_info.get('risk_factors', []))
    except Exception:
        pass

    scan = ScanHistory(
        url=url, domain=domain,
        threat_score=result['threat_score'],
        risk_category=result['risk_category'],
        scan_type='url',
        domain_age_days=domain_info.get('domain_age_days'),
<<<<<<< HEAD
        extra_data=json.dumps({
            'risk_factors':    result.get('risk_factors', []),
            'recommendations': result.get('recommendations', []),
        }),
=======
        extra_data=json.dumps({'risk_factors': result.get('risk_factors', []),
                               'recommendations': result.get('recommendations', [])}),
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
    )
    db.session.add(scan)
    db.session.commit()

    return _api_response(data={
<<<<<<< HEAD
        'scan_id':        scan.id,
        'url':            url,
        'threat_score':   result['threat_score'],
        'risk_category':  result['risk_category'],
        'risk_factors':   result['risk_factors'],
        'recommendations':result['recommendations'],
        'domain_age_days':domain_info.get('domain_age_days'),
    })


# ── /api/scan-journal  (v2 new) ─────────────────────────────────────────────
@api_bp.route('/scan-journal', methods=['POST'])
@limiter.limit('20 per minute')
def api_scan_journal():
    """
    POST JSON: {"url": "https://suspicious-journal.com"}
    Returns full journal authenticity analysis + hybrid score.
    """
    body = request.get_json(silent=True) or {}
    url  = sanitize_url(body.get('url', '').strip())
    if not url:
        return _api_response(error='URL is required', status=400)

    url_result  = analyze_url(url)
    domain      = extract_domain(url)
    domain_info = {}
    try:
        domain_info = get_domain_intelligence(url)
        url_result['risk_factors'].extend(domain_info.get('risk_factors', []))
    except Exception:
        pass

    reputation = {}
    try:
        from app.services.reputation_service import get_reputation_verdict
        reputation = get_reputation_verdict(url, current_app.config)
    except Exception:
        pass

    journal_result = {}
    try:
        from app.services.journal_analyzer import analyze_journal
        from app.services.website_classifier import classify_website  # noqa — imported for logging
        journal_result = analyze_journal(url, domain_info)
    except Exception as e:
        journal_result = {'error': str(e)}

    hybrid = {}
    try:
        from app.services.hybrid_scorer import compute_hybrid_score
        hybrid = compute_hybrid_score(url_result, domain_info, reputation, journal_result)
    except Exception:
        pass

    final_score   = journal_result.get('journal_score', url_result['threat_score'])
    risk_category = journal_result.get('risk_category', 'Unknown')

    scan = ScanHistory(
        url=url, domain=domain,
        threat_score=final_score,
        risk_category=risk_category,
        scan_type='journal',
        domain_age_days=domain_info.get('domain_age_days'),
        journal_score=journal_result.get('journal_score'),
        journal_data=json.dumps(journal_result),
        hybrid_score=hybrid.get('final_score'),
        phishing_prob=hybrid.get('phishing_probability'),
        extra_data=json.dumps({
            'risk_factors':    url_result.get('risk_factors', []),
            'recommendations': journal_result.get('recommendations', []),
        }),
    )
    db.session.add(scan)
    db.session.commit()

    return _api_response(data={
        'scan_id':              scan.id,
        'url':                  url,
        'domain':               domain,
        'threat_score':         final_score,
        'risk_category':        risk_category,
        # v3: website classification
        'website_type':         journal_result.get('website_type', 'unknown'),
        'website_type_display': journal_result.get('website_type_display', ''),
        'organisation':         journal_result.get('organisation', ''),
        'country':              journal_result.get('country', ''),
        'is_known_safe':        journal_result.get('is_known_safe', False),
        # scores
        'journal_score':        journal_result.get('journal_score'),
        'authenticity_score':   journal_result.get('authenticity_score'),
        'phishing_probability': hybrid.get('phishing_probability'),
        'hybrid_score':         hybrid.get('final_score'),
        'score_basis':          'heuristic-estimate',
        # trust dimensions
        'trust_dimensions':     journal_result.get('trust_dimensions', {}),
        # verification
        'risk_factors':         url_result.get('risk_factors', []),
        'positive_signals':     journal_result.get('positive_signals', []),
        'conflicts':            journal_result.get('conflicts', []),
        'recommendations':      journal_result.get('recommendations', []),
        'api_checks':           journal_result.get('api_checks', {}),
        'content_findings':     journal_result.get('content_findings', {}),
        # explainability
        'explainability':       journal_result.get('explainability', hybrid.get('explainability', '')),
        'sub_scores':           hybrid.get('sub_scores', {}),
        'classification_evidence': journal_result.get('classification_evidence', []),
    })


# ── /api/journal-check  (v2 quick-check alias) ──────────────────────────────
@api_bp.route('/journal-check', methods=['GET'])
@limiter.limit('30 per minute')
def api_journal_check():
    """
    GET /api/journal-check?url=https://... — lightweight check.
    Returns: {authentic: bool, risk_category, journal_score}
    """
    url = sanitize_url(request.args.get('url', '').strip())
    if not url:
        return _api_response(error='url parameter required', status=400)

    try:
        from app.services.journal_analyzer import analyze_journal
        jr = analyze_journal(url)
        return _api_response(data={
            'url':               url,
            'journal_score':     jr.get('journal_score'),
            'authenticity_score':jr.get('authenticity_score'),
            'risk_category':     jr.get('risk_category'),
            'doaj_found':        jr.get('api_checks', {}).get('doaj', {}).get('found', False),
            'crossref_found':    jr.get('api_checks', {}).get('crossref', {}).get('found', False),
            'risk_factors':      jr.get('risk_factors', []),
        })
    except Exception as e:
        return _api_response(error=str(e), status=500)


# ── /api/scan-qr  (v1 preserved) ───────────────────────────────────────────
=======
        'scan_id': scan.id,
        'url': url,
        'threat_score': result['threat_score'],
        'risk_category': result['risk_category'],
        'risk_factors': result['risk_factors'],
        'recommendations': result['recommendations'],
        'domain_age_days': domain_info.get('domain_age_days'),
    })


# ── /api/scan-qr ───────────────────────────────────────────────────────────
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
@api_bp.route('/scan-qr', methods=['POST'])
@limiter.limit('20 per minute')
def api_scan_qr():
    if 'file' not in request.files:
        return _api_response(error='No file provided', status=400)
    file = request.files['file']
    if not allowed_file(file.filename, current_app.config['ALLOWED_IMAGE_EXTENSIONS']):
        return _api_response(error='Invalid file type', status=400)

    upload_dir = current_app.config['UPLOAD_DIR']
    filename = f'api_qr_{uuid.uuid4().hex[:10]}_{secure_filename(file.filename)}'
    filepath = os.path.join(upload_dir, filename)
    file.save(filepath)

    try:
        qr_result = analyze_qr_image(filepath)
    finally:
        try:
            os.remove(filepath)
        except Exception:
            pass

    scan = ScanHistory(
        url=qr_result.get('url_analysis', {}).get('url') if qr_result.get('url_analysis') else None,
        threat_score=qr_result.get('threat_score', 0),
        risk_category=qr_result.get('risk_category', 'Safe'),
        scan_type='qr',
        qr_content=qr_result.get('raw_content'),
        extra_data=json.dumps({'risk_factors': qr_result.get('risk_factors', [])}),
    )
    db.session.add(scan)
    db.session.commit()

    return _api_response(data={
<<<<<<< HEAD
        'scan_id':      scan.id,
        'qr_found':     qr_result.get('qr_found'),
        'raw_content':  qr_result.get('raw_content'),
        'content_type': qr_result.get('classification', {}).get('content_type'),
        'threat_score': qr_result.get('threat_score'),
        'risk_category':qr_result.get('risk_category'),
=======
        'scan_id': scan.id,
        'qr_found': qr_result.get('qr_found'),
        'raw_content': qr_result.get('raw_content'),
        'content_type': qr_result.get('classification', {}).get('content_type'),
        'threat_score': qr_result.get('threat_score'),
        'risk_category': qr_result.get('risk_category'),
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
        'risk_factors': qr_result.get('risk_factors', []),
    })


<<<<<<< HEAD
# ── /api/scan-image  (v1 preserved) ────────────────────────────────────────
=======
# ── /api/scan-image ────────────────────────────────────────────────────────
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
@api_bp.route('/scan-image', methods=['POST'])
@limiter.limit('20 per minute')
def api_scan_image():
    if 'file' not in request.files:
        return _api_response(error='No file provided', status=400)
    file = request.files['file']
    if not allowed_file(file.filename, current_app.config['ALLOWED_IMAGE_EXTENSIONS']):
        return _api_response(error='Invalid file type', status=400)

    upload_dir = current_app.config['UPLOAD_DIR']
    filename = f'api_img_{uuid.uuid4().hex[:10]}_{secure_filename(file.filename)}'
    filepath = os.path.join(upload_dir, filename)
    file.save(filepath)

    try:
        img_result = analyze_image(filepath)
    finally:
        try:
            os.remove(filepath)
        except Exception:
            pass

    scan = ScanHistory(
        threat_score=img_result.get('threat_score', 0),
        risk_category=img_result.get('risk_category', 'Safe'),
        scan_type='image',
        extra_data=json.dumps({'risk_factors': img_result.get('risk_factors', [])}),
    )
    db.session.add(scan)
    db.session.commit()

    return _api_response(data={
<<<<<<< HEAD
        'scan_id':        scan.id,
        'threat_score':   img_result['threat_score'],
        'risk_category':  img_result['risk_category'],
        'qr_codes':       img_result.get('qr_codes', []),
        'embedded_urls':  img_result.get('embedded_urls', []),
        'scam_keywords':  img_result.get('scam_keywords', []),
        'risk_factors':   img_result.get('risk_factors', []),
    })


# ── /api/history  (v1 preserved) ────────────────────────────────────────────
@api_bp.route('/history', methods=['GET'])
def api_history():
    page     = request.args.get('page', 1, type=int)
=======
        'scan_id': scan.id,
        'threat_score': img_result['threat_score'],
        'risk_category': img_result['risk_category'],
        'qr_codes': img_result.get('qr_codes', []),
        'embedded_urls': img_result.get('embedded_urls', []),
        'scam_keywords': img_result.get('scam_keywords', []),
        'risk_factors': img_result.get('risk_factors', []),
    })


# ── /api/history ───────────────────────────────────────────────────────────
@api_bp.route('/history', methods=['GET'])
def api_history():
    page = request.args.get('page', 1, type=int)
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    category = request.args.get('category')
    scan_type = request.args.get('type')

    q = ScanHistory.query
    if category:
        q = q.filter_by(risk_category=category)
    if scan_type:
        q = q.filter_by(scan_type=scan_type)

<<<<<<< HEAD
    pagination = q.order_by(ScanHistory.scan_date.desc()).paginate(
        page=page, per_page=per_page
    )
    return _api_response(data={
        'items':  [s.to_dict() for s in pagination.items],
        'total':  pagination.total,
        'pages':  pagination.pages,
        'page':   page,
    })


# ── /api/stats  (v1 preserved + journal counts) ─────────────────────────────
@api_bp.route('/stats', methods=['GET'])
def api_stats():
    total = ScanHistory.query.count()
    cats  = {c: ScanHistory.query.filter_by(risk_category=c).count()
             for c in ['Safe', 'Suspicious', 'High Risk', 'Critical Threat']}
    types = {t: ScanHistory.query.filter_by(scan_type=t).count()
             for t in ['url', 'qr', 'image', 'journal']}

    return _api_response(data={
        'total_scans':    total,
        'by_category':    cats,
        'by_type':        types,
        'threats_blocked':cats.get('High Risk', 0) + cats.get('Critical Threat', 0),
    })


# ── /api/report  (v1 preserved) ─────────────────────────────────────────────
@api_bp.route('/report/<int:scan_id>', methods=['GET'])
def api_report(scan_id):
    scan  = ScanHistory.query.get_or_404(scan_id)
=======
    pagination = q.order_by(ScanHistory.scan_date.desc()).paginate(page=page, per_page=per_page)

    return _api_response(data={
        'items': [s.to_dict() for s in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'page': page,
    })


# ── /api/stats ─────────────────────────────────────────────────────────────
@api_bp.route('/stats', methods=['GET'])
def api_stats():
    total = ScanHistory.query.count()
    cats = {}
    for cat in ['Safe', 'Suspicious', 'High Risk', 'Critical Threat']:
        cats[cat] = ScanHistory.query.filter_by(risk_category=cat).count()

    types = {}
    for t in ['url', 'qr', 'image']:
        types[t] = ScanHistory.query.filter_by(scan_type=t).count()

    return _api_response(data={
        'total_scans': total,
        'by_category': cats,
        'by_type': types,
        'threats_blocked': cats.get('High Risk', 0) + cats.get('Critical Threat', 0),
    })


# ── /api/report ────────────────────────────────────────────────────────────
@api_bp.route('/report/<int:scan_id>', methods=['GET'])
def api_report(scan_id):
    scan = ScanHistory.query.get_or_404(scan_id)
>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
    extra = json.loads(scan.extra_data or '{}')

    from app.services.pdf_report import generate_pdf_report
    pdf_path = generate_pdf_report({
<<<<<<< HEAD
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
        # v2 additions
        'journal_score':  scan.journal_score,
        'hybrid_score':   scan.hybrid_score,
        'phishing_prob':  scan.phishing_prob,
        'journal_data':   json.loads(scan.journal_data) if scan.journal_data else {},
    })

    if not pdf_path:
        return _api_response(
            error='PDF generation failed (reportlab may not be installed)', status=500
        )
=======
        'id': scan.id,
        'url': scan.url,
        'domain': scan.domain,
        'threat_score': scan.threat_score,
        'risk_category': scan.risk_category,
        'scan_date': scan.scan_date.isoformat() if scan.scan_date else '',
        'scan_type': scan.scan_type,
        'qr_content': scan.qr_content,
        'risk_factors': extra.get('risk_factors', []),
        'recommendations': extra.get('recommendations', []),
        'screenshot_path': scan.screenshot_path,
    })

    if not pdf_path:
        return _api_response(error='PDF generation failed (reportlab may not be installed)', status=500)

>>>>>>> 99727748a15251a8f4d92432e4608bc61952b66f
    return _api_response(data={'pdf_url': f'/static/{pdf_path}', 'scan_id': scan_id})
