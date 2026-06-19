"""NEURAL-X — Basic test suite"""

import pytest
import json
from app import create_app, db


@pytest.fixture
def app():
    app = create_app('testing')
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


# ── Route tests ────────────────────────────────────────────
def test_index(client):
    r = client.get('/')
    assert r.status_code == 200
    assert b'NEURAL-X' in r.data or b'neural' in r.data.lower()


def test_scan_url_get(client):
    r = client.get('/scan/url')
    assert r.status_code == 200


def test_scan_qr_get(client):
    r = client.get('/scan/qr')
    assert r.status_code == 200


def test_scan_image_get(client):
    r = client.get('/scan/image')
    assert r.status_code == 200


def test_history_get(client):
    r = client.get('/history/')
    assert r.status_code == 200


def test_admin_get(client):
    r = client.get('/admin/')
    assert r.status_code == 200


def test_api_stats(client):
    r = client.get('/api/stats')
    assert r.status_code == 200
    data = json.loads(r.data)
    assert data['status'] == 'success'
    assert 'total_scans' in data['data']


def test_api_history(client):
    r = client.get('/api/history')
    assert r.status_code == 200
    data = json.loads(r.data)
    assert data['status'] == 'success'


def test_api_scan_url_missing(client):
    r = client.post('/api/scan-url',
                    data=json.dumps({}),
                    content_type='application/json')
    assert r.status_code == 400


# ── Service unit tests ─────────────────────────────────────
def test_url_analyzer_safe():
    from app.services.url_analyzer import analyze_url
    result = analyze_url('https://www.google.com')
    assert result['threat_score'] < 45
    assert result['risk_category'] in ['Safe', 'Suspicious']


def test_url_analyzer_phishing():
    from app.services.url_analyzer import analyze_url
    result = analyze_url('http://paypal-secure-verify-account.tk/login?update=1')
    assert result['threat_score'] > 40


def test_url_analyzer_ip():
    from app.services.url_analyzer import analyze_url
    result = analyze_url('http://192.168.1.1/login')
    assert result['threat_score'] >= 30


def test_qr_classifier_url():
    from app.services.qr_analyzer import classify_qr_content
    r = classify_qr_content('https://www.example.com')
    assert r['content_type'] == 'url'
    assert r['is_url'] is True


def test_qr_classifier_wifi():
    from app.services.qr_analyzer import classify_qr_content
    r = classify_qr_content('WIFI:S:MyNetwork;T:WPA;P:mypassword;;')
    assert r['content_type'] == 'wifi'


def test_qr_classifier_phone():
    from app.services.qr_analyzer import classify_qr_content
    r = classify_qr_content('tel:+1234567890')
    assert r['content_type'] == 'phone'


def test_qr_classifier_email():
    from app.services.qr_analyzer import classify_qr_content
    r = classify_qr_content('mailto:test@example.com')
    assert r['content_type'] == 'email'


def test_qr_classifier_text():
    from app.services.qr_analyzer import classify_qr_content
    r = classify_qr_content('Hello, World!')
    assert r['content_type'] == 'text'
    assert r['is_url'] is False


def test_domain_extract():
    from app.services.domain_intel import extract_domain
    assert extract_domain('https://www.example.com/path') == 'example.com'
    assert extract_domain('http://sub.domain.co.uk') == 'domain.co.uk'


def test_classify_risk():
    from app.services.url_analyzer import classify_risk
    assert classify_risk(10) == 'Safe'
    assert classify_risk(30) == 'Suspicious'
    assert classify_risk(55) == 'High Risk'
    assert classify_risk(80) == 'Critical Threat'
